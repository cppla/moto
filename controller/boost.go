package controller

import (
	"context"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	boostWinnerTTL       = 30 * time.Second // 胜出线路缓存时长
	boostRevalidateAfter = boostWinnerTTL / 2
)

type boostWinnerEntry struct {
	addr    string
	expires time.Time
}

var boostWinnerCache sync.Map

const boostWinnerCacheMax = 256 // 防止规则极多导致无限增长

type dialResult struct {
	conn net.Conn
	addr string
}

func loadBoostWinner(ruleName string) (string, bool, time.Time) {
	if v, ok := boostWinnerCache.Load(ruleName); ok {
		entry := v.(boostWinnerEntry)
		if time.Now().Before(entry.expires) {
			return entry.addr, true, entry.expires
		}
		boostWinnerCache.Delete(ruleName)
	}
	return "", false, time.Time{}
}

func storeBoostWinner(ruleName, addr string) {
	// 简单的 size 控制：超过上限时随机淘汰一个（遍历首个）。
	count := 0
	boostWinnerCache.Range(func(k, v any) bool {
		count++
		if count > boostWinnerCacheMax {
			// 淘汰当前这个并停止
			boostWinnerCache.Delete(k)
			return false
		}
		return true
	})
	boostWinnerCache.Store(ruleName, boostWinnerEntry{addr: addr, expires: time.Now().Add(boostWinnerTTL)})
}

// 不再单独提供显式 drop 接口，超时或拨号失败自动失效。

// lazyRevalidate 在后台重新跑一次竞速，不打断现有请求；若发现更快线路则更新缓存。
func lazyRevalidate(rule *config.Rule) {
	// 只有多于一个目标才有意义
	if len(rule.Targets) < 2 {
		return
	}
	// 设定一个较短的决策超时，避免后台任务堆积。
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	switchBetter := make(chan dialResult, 1)
	// 启动并发拨号
	for _, v := range rule.Targets {
		addr := v.Address
		go func(a string) {
			if c, err := outboundDial(a); err == nil {
				select {
				case switchBetter <- dialResult{conn: c, addr: a}:
				case <-ctx.Done():
					c.Close()
				}
			}
		}(addr)
	}
	var best dialResult
	select {
	case best = <-switchBetter:
		cancel()
	case <-ctx.Done():
		return
	}
	if tc, ok := best.conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	storeBoostWinner(rule.Name, best.addr)
	utils.Logger.Debug("懒惰刷新winner",
		zap.String("ruleName", rule.Name),
		zap.String("targetAddr", best.conn.RemoteAddr().String()))
	best.conn.Close()
}

// HandleBoost 同时发起多路拨号，挑选最先成功的连接并套上单边加速。
func HandleBoost(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	decisionBegin := time.Now()

	if addr, ok, exp := loadBoostWinner(rule.Name); ok {
		// 命中缓存后，判断是否需要后台懒惰校验。
		var triggerLazy bool
		if !exp.IsZero() {
			lifeLeft := time.Until(exp)
			if lifeLeft < boostRevalidateAfter {
				triggerLazy = true
			}
		}
		if cachedConn, err := outboundDial(addr); err == nil {
			if tc, ok := cachedConn.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(30 * time.Second)
			}
			storeBoostWinner(rule.Name, addr)
			fields := []zap.Field{
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", cachedConn.RemoteAddr().String()),
				zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
				zap.Bool("boostCacheHit", true),
			}
			if triggerLazy {
				fields = append(fields, zap.Bool("boostLazyRefresh", true))
			}
			utils.Logger.Debug("建立连接", fields...)

			if triggerLazy {
				go lazyRevalidate(rule)
			}

			defer cachedConn.Close()

			go func() {
				io.Copy(conn, cachedConn)
				conn.Close()
				cachedConn.Close()
			}()
			io.Copy(cachedConn, conn)
			return
		}
		// 缓存线路拨号失败：直接从缓存移除，下次重新竞速
		boostWinnerCache.Delete(rule.Name)
	}

	// 并发拨号选择最快线路
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switchBetter := make(chan dialResult, 1)
	for _, v := range rule.Targets {
		go func(address string) {
			if tryGetQuickConn, err := outboundDial(address); err == nil {
				select {
				case switchBetter <- dialResult{conn: tryGetQuickConn, addr: address}:
				case <-ctx.Done():
					tryGetQuickConn.Close()
				}
			}
		}(v.Address)
	}
	// 全部连接失败： 所有线路延迟或中断
	dtx, dance := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(rule.Timeout))
	defer dance()

	var winner dialResult
	select {
	case winner = <-switchBetter:
		cancel()
	case <-dtx.Done():
		utils.Logger.Error("加速决策失败：所有线路均不可用",
			zap.String("ruleName", rule.Name))
		return
	}

	if tc, ok := winner.conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	storeBoostWinner(rule.Name, winner.addr)

	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", winner.conn.RemoteAddr().String()),
		zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
		zap.Bool("boostCacheHit", false))

	defer winner.conn.Close()

	go func() {
		io.Copy(conn, winner.conn)
		conn.Close()
		winner.conn.Close()
	}()
	io.Copy(winner.conn, conn)
}
