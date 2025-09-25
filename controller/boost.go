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

const boostWinnerTTL = 60 * time.Second

type boostWinnerEntry struct {
	addr    string
	expires time.Time
}

var boostWinnerCache sync.Map

type dialResult struct {
	conn net.Conn
	addr string
	used bool
}

func loadBoostWinner(ruleName string) (string, bool) {
	if v, ok := boostWinnerCache.Load(ruleName); ok {
		entry := v.(boostWinnerEntry)
		if time.Now().Before(entry.expires) {
			return entry.addr, true
		}
		boostWinnerCache.Delete(ruleName)
	}
	return "", false
}

func storeBoostWinner(ruleName, addr string) {
	boostWinnerCache.Store(ruleName, boostWinnerEntry{addr: addr, expires: time.Now().Add(boostWinnerTTL)})
}

func dropBoostWinner(ruleName string) {
	boostWinnerCache.Delete(ruleName)
}

// HandleBoost 同时发起多路拨号，挑选最先成功的连接并套上单边加速。
func HandleBoost(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	decisionBegin := time.Now()

	if addr, ok := loadBoostWinner(rule.Name); ok {
		if cachedConn, used, err := outboundDial(addr); err == nil {
			if !used {
				cachedConn = newOneSidedConn(cachedConn)
			}
			storeBoostWinner(rule.Name, addr)
			utils.Logger.Debug("建立连接",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", cachedConn.RemoteAddr().String()),
				zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
				zap.Bool("boostCacheHit", true))

			defer cachedConn.Close()

			go func() {
				io.Copy(conn, cachedConn)
				conn.Close()
				cachedConn.Close()
			}()
			io.Copy(cachedConn, conn)
			return
		}
		dropBoostWinner(rule.Name)
	}

	//智能选择最先连上的优质线路。 未用的TCP主动关闭连接。
	//决策时间超过timeout主动关闭，超过300ms🚀没有意义
	//todo： 这里如何保持长久连接？
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switchBetter := make(chan dialResult, 1)
	for _, v := range rule.Targets {
		go func(address string) {
			if tryGetQuickConn, used, err := outboundDial(address); err == nil {
				select {
				case switchBetter <- dialResult{conn: tryGetQuickConn, addr: address, used: used}:
				case <-ctx.Done():
					tryGetQuickConn.Close()
				}
			}
		}(v.Address)
	}
	//全部连接失败： 最恶劣的情况，全部线路延迟大或中断。
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

	if !winner.used {
		winner.conn = newOneSidedConn(winner.conn)
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
