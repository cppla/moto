package controller

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"moto/config"
	"moto/utils"
	"net"
	"sort"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// Simple framed multiplex tunnel with adaptive multi-send across multiple links.
// Frame format:
// magic[4] = 'M','O','T','O'
// flags u8  (1=SYN,2=FIN,4=RST,8=DATA)
// streamID u32
// seq u32
// length u32
// payload [length]

const (
	flagSYN  = 1
	flagFIN  = 2
	flagRST  = 4
	flagDATA = 8
	flagACK  = 16
	flagPING = 32
	flagPONG = 64
	flagNACK = 128
)

var magic = [4]byte{'M', 'O', 'T', 'O'}

type frame struct {
	flags    uint8
	streamID uint32
	seq      uint32
	payload  []byte
}

func writeFrame(w io.Writer, fr frame) error {
	hdr := make([]byte, 4+1+4+4+4)
	copy(hdr[0:4], magic[:])
	hdr[4] = fr.flags
	binary.BigEndian.PutUint32(hdr[5:9], fr.streamID)
	binary.BigEndian.PutUint32(hdr[9:13], fr.seq)
	binary.BigEndian.PutUint32(hdr[13:17], uint32(len(fr.payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(fr.payload) > 0 {
		_, err := w.Write(fr.payload)
		return err
	}
	return nil
}

func readFrame(r *bufio.Reader, maxPayload int) (frame, error) {
	var fr frame
	header := make([]byte, 17)
	if _, err := io.ReadFull(r, header); err != nil {
		return fr, err
	}
	if header[0] != 'M' || header[1] != 'O' || header[2] != 'T' || header[3] != 'O' {
		return fr, errors.New("invalid magic")
	}
	fr.flags = header[4]
	fr.streamID = binary.BigEndian.Uint32(header[5:9])
	fr.seq = binary.BigEndian.Uint32(header[9:13])
	ln := int(binary.BigEndian.Uint32(header[13:17]))
	if ln < 0 || ln > maxPayload {
		return fr, fmt.Errorf("invalid length %d", ln)
	}
	if ln > 0 {
		fr.payload = make([]byte, ln)
		if _, err := io.ReadFull(r, fr.payload); err != nil {
			return fr, err
		}
	}
	return fr, nil
}

// accelerator manager
type accelManager struct {
	cfg *config.Accelerator

	// client side fields
	tunnels []*accelTunnel
	tunMu   sync.RWMutex

	// streams on client side: streamID -> *streamConn
	streams    map[uint32]*streamConn
	streamsMu  sync.RWMutex
	nextStream uint32

	// server side: active upstream conns per stream
	upstreams   map[uint32]net.Conn
	upMu        sync.RWMutex
	upExpectSeq map[uint32]uint32
	upPending   map[uint32]map[uint32][]byte // streamID -> seq -> payload

	// loss/adaptation stats (per process side)
	statsMu sync.Mutex
	currDup int // current adaptive duplication (1..5)

	// server-side downlink cache for selective retransmission (NACK)
	downMu         sync.RWMutex
	downCache      map[uint32]map[uint32][]byte // streamID -> seq -> payload
	downCacheFloor map[uint32]uint32            // per stream lowest retained seq for pruning

	// adaptive frame size
	dynMu        sync.RWMutex
	dynFrameSize int
}

type accelTunnel struct {
	conn   io.ReadWriteCloser
	rd     *bufio.Reader
	wrMu   sync.Mutex
	closed chan struct{}

	// human-readable remote peer (addr)
	peer string

	// health metrics
	statMu     sync.RWMutex
	rttEWMA    float64 // ms
	jitterEWMA float64 // ms
	samples    int

	// per-tunnel adaptation stats
	sentCount int // frames sent (DATA/FIN) via this tunnel in window
	ackCount  int // ACKs received on this tunnel in window
	currDup   int // current adaptive multiplier for this tunnel (1..5)
}

// getDup returns the current per-tunnel multiplier (1..5), defaults to 1
func (t *accelTunnel) getDup() int {
	t.statMu.RLock()
	d := t.currDup
	t.statMu.RUnlock()
	if d < 1 {
		d = 1
	}
	if d > 5 {
		d = 5
	}
	return d
}

// snapshotPeers returns a copy of current tunnel peers for logging
func (m *accelManager) snapshotPeers() []string {
	m.tunMu.RLock()
	defer m.tunMu.RUnlock()
	res := make([]string, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		res = append(res, t.peer)
	}
	return res
}

var gAccel *accelManager
var onceAccel sync.Once

// Init accelerator according to role
func InitAccelerator() {
	if config.GlobalCfg.Accelerator == nil || !config.GlobalCfg.Accelerator.Enabled {
		return
	}
	onceAccel.Do(func() {
		gAccel = &accelManager{
			cfg:            config.GlobalCfg.Accelerator,
			streams:        make(map[uint32]*streamConn),
			upstreams:      make(map[uint32]net.Conn),
			upExpectSeq:    make(map[uint32]uint32),
			upPending:      make(map[uint32]map[uint32][]byte),
			downCache:      make(map[uint32]map[uint32][]byte),
			downCacheFloor: make(map[uint32]uint32),
		}
		if gAccel.cfg.Role == "client" {
			gAccel.startClient()
			gAccel.startAdaptation()
		} else if gAccel.cfg.Role == "server" {
			go gAccel.startServer()
			gAccel.startAdaptation()
		}
		// init dynamic frame size from baseline (dup==1 rule -> frameSize)
		fs := gAccel.baseFrameSize()
		gAccel.dynMu.Lock()
		gAccel.dynFrameSize = fs
		gAccel.dynMu.Unlock()
	})
}

// Client: establish N persistent tunnels
func (m *accelManager) startClient() {
	n := m.cfg.Tunnels
	if n <= 0 {
		n = 2
	}
	for i := 0; i < n; i++ {
		go func(idx int) {
			for {
				// pick remote (round-robin over remotes)
				if len(m.cfg.Remotes) == 0 {
					utils.Logger.Warn("ACC: 未配置任何远端 remotes")
					time.Sleep(time.Second)
					continue
				}
				remote := m.cfg.Remotes[idx%len(m.cfg.Remotes)]
				c, err := m.dialTransport(remote)
				if err != nil {
					utils.Logger.Warn("ACC: 拨号远端失败", zap.String("remote", remote), zap.Error(err))
					time.Sleep(time.Second)
					continue
				}
				// TCP specific tuning
				if nc, ok := c.(net.Conn); ok {
					if tcp, ok2 := nc.(*net.TCPConn); ok2 {
						_ = tcp.SetNoDelay(true)
						_ = tcp.SetKeepAlive(true)
						_ = tcp.SetKeepAlivePeriod(30 * time.Second)
					}
				}
				t := &accelTunnel{conn: c, rd: bufio.NewReaderSize(c, 64*1024), closed: make(chan struct{}), peer: remote}
				m.tunMu.Lock()
				m.tunnels = append(m.tunnels, t)
				m.tunMu.Unlock()
				utils.Logger.Info("ACC: 隧道已建立", zap.String("remote", remote))
				// start health probing
				go m.probeTunnel(t)
				m.handleTunnelClient(t)
				utils.Logger.Warn("ACC: 隧道断开")
				c.Close()
				// remove from slice
				m.tunMu.Lock()
				for i := range m.tunnels {
					if m.tunnels[i] == t {
						m.tunnels = append(m.tunnels[:i], m.tunnels[i+1:]...)
						break
					}
				}
				m.tunMu.Unlock()
				time.Sleep(time.Second)
			}
		}(i)
	}
}

// Server: accept tunnels
func (m *accelManager) startServer() {
	if m.cfg.Transport == "quic" {
		m.startServerQUIC()
		return
	}
	// TCP server
	ln, err := net.Listen("tcp", m.cfg.Listen)
	if err != nil {
		utils.Logger.Error("ACC: 监听失败 (tcp)", zap.String("listen", m.cfg.Listen), zap.Error(err))
		return
	}
	utils.Logger.Info("ACC: 服务器开始监听 (tcp)", zap.String("listen", m.cfg.Listen))
	for {
		c, err := ln.Accept()
		if err != nil {
			utils.Logger.Error("ACC: 接受连接失败", zap.Error(err))
			time.Sleep(time.Second)
			continue
		}
		t := &accelTunnel{conn: c, rd: bufio.NewReaderSize(c, 64*1024), closed: make(chan struct{}), peer: c.RemoteAddr().String()}
		m.tunMu.Lock()
		m.tunnels = append(m.tunnels, t)
		m.tunMu.Unlock()
		utils.Logger.Info("ACC: 服务器隧道已建立", zap.String("peer", c.RemoteAddr().String()))
		go func() {
			// start health probing
			go m.probeTunnel(t)
			m.handleTunnelServer(t)
			c.Close()
			// remove
			m.tunMu.Lock()
			for i := range m.tunnels {
				if m.tunnels[i] == t {
					m.tunnels = append(m.tunnels[:i], m.tunnels[i+1:]...)
					break
				}
			}
			m.tunMu.Unlock()
			utils.Logger.Warn("ACC: 服务器隧道断开")
		}()
	}
}

// client side tunnel reader: delivers frames to streamConns
func (m *accelManager) handleTunnelClient(t *accelTunnel) {
	max := m.getReadMax()
	for {
		fr, err := readFrame(t.rd, max)
		if err != nil {
			close(t.closed)
			return
		}
		// handle ACK for our uplink frames
		if fr.flags == flagACK {
			// uplink ACKs counted per-tunnel
			t.statMu.Lock()
			t.ackCount++
			t.statMu.Unlock()
			continue
		}
		if fr.flags == flagPING {
			// echo back PONG with same payload
			_ = sendOnTunnel(t, frame{flags: flagPONG, streamID: fr.streamID, seq: fr.seq, payload: fr.payload})
			continue
		}
		if fr.flags == flagPONG {
			if len(fr.payload) >= 8 {
				// payload holds int64 nano timestamp
				ts := int64(binary.BigEndian.Uint64(fr.payload[:8]))
				rtt := float64(time.Since(time.Unix(0, ts)).Milliseconds())
				t.updateRTT(rtt)
			}
			continue
		}
		// dispatch
		m.streamsMu.RLock()
		sc := m.streams[fr.streamID]
		m.streamsMu.RUnlock()
		if sc == nil {
			// unknown stream; ignore
			continue
		}
		// send ACK back for downlink frames to allow server to adapt
		if fr.flags == flagDATA || fr.flags == flagFIN {
			_ = sendOnTunnel(t, frame{flags: flagACK, streamID: fr.streamID, seq: fr.seq})
		}
		// if we see a gap for this stream, issue NACK asking for next expected seq
		if fr.flags == flagDATA {
			sc.readMu.Lock()
			expect := sc.readSeq
			if fr.seq > expect {
				// request retransmission of the missing seq 'expect'
				_ = sendOnTunnel(t, frame{flags: flagNACK, streamID: fr.streamID, seq: expect})
			}
			sc.readMu.Unlock()
		}
		sc.onFrame(fr)
	}
}

// server side tunnel reader: handles SYN/Data for upstreams
func (m *accelManager) handleTunnelServer(t *accelTunnel) {
	max := m.getReadMax()
	for {
		fr, err := readFrame(t.rd, max)
		if err != nil {
			return
		}
		switch fr.flags {
		case flagSYN:
			// payload is target address
			targetAddr := string(fr.payload)
			go m.acceptUpstream(fr.streamID, targetAddr, t)
		case flagDATA:
			// ACK back for client's uplink frame
			_ = sendOnTunnel(t, frame{flags: flagACK, streamID: fr.streamID, seq: fr.seq})
			m.upMu.RLock()
			up := m.upstreams[fr.streamID]
			m.upMu.RUnlock()
			if up == nil { // not yet ready, buffer by seq
				m.upMu.Lock()
				if _, ok := m.upPending[fr.streamID]; !ok {
					m.upPending[fr.streamID] = make(map[uint32][]byte)
				}
				m.upPending[fr.streamID][fr.seq] = fr.payload
				m.upMu.Unlock()
				continue
			}
			// write to upstream in order by seq
			m.writeInOrderServer(fr.streamID, up, fr.seq, fr.payload)
		case flagNACK:
			// client requests retransmission of seq=fr.seq for stream
			sid := fr.streamID
			seq := fr.seq
			m.downMu.RLock()
			if cache, ok := m.downCache[sid]; ok {
				if pld, ok2 := cache[seq]; ok2 {
					// retransmit on primary (t) to reduce duplication
					_ = sendOnTunnel(t, frame{flags: flagDATA, streamID: sid, seq: seq, payload: pld})
				}
			}
			m.downMu.RUnlock()
		case flagACK:
			// ACK for our downlink frames -> per-tunnel stats
			t.statMu.Lock()
			t.ackCount++
			t.statMu.Unlock()
			// prune cache for stream up to acked seq
			sid := fr.streamID
			acked := fr.seq
			m.downMu.Lock()
			floor := m.downCacheFloor[sid]
			if acked >= floor {
				if cache, ok := m.downCache[sid]; ok {
					for s := floor; s <= acked; s++ {
						delete(cache, s)
					}
				}
				m.downCacheFloor[sid] = acked + 1
			}
			m.downMu.Unlock()
		case flagPING:
			// echo back PONG
			_ = sendOnTunnel(t, frame{flags: flagPONG, streamID: fr.streamID, seq: fr.seq, payload: fr.payload})
		case flagPONG:
			if len(fr.payload) >= 8 {
				ts := int64(binary.BigEndian.Uint64(fr.payload[:8]))
				rtt := float64(time.Since(time.Unix(0, ts)).Milliseconds())
				t.updateRTT(rtt)
			}
		case flagFIN:
			m.upMu.Lock()
			if up := m.upstreams[fr.streamID]; up != nil {
				up.Close()
			}
			delete(m.upstreams, fr.streamID)
			delete(m.upExpectSeq, fr.streamID)
			delete(m.upPending, fr.streamID)
			m.upMu.Unlock()
			// clear downlink cache for this stream
			m.downMu.Lock()
			delete(m.downCache, fr.streamID)
			delete(m.downCacheFloor, fr.streamID)
			m.downMu.Unlock()
		}
	}
}

func (m *accelManager) acceptUpstream(streamID uint32, addr string, t *accelTunnel) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		// send RST back on the same tunnel
		_ = sendOnTunnel(t, frame{flags: flagRST, streamID: streamID, seq: 0, payload: nil})
		return
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	m.upMu.Lock()
	m.upstreams[streamID] = c
	m.upExpectSeq[streamID] = 1
	pending := m.upPending[streamID]
	m.upMu.Unlock()

	// start pump back to client
	go m.pipeUpToClient(streamID, c, t)

	// flush any pending in order
	if len(pending) > 0 {
		// write pending in order starting from 1
		m.upMu.Lock()
		expect := m.upExpectSeq[streamID]
		for {
			data, ok := pending[expect]
			if !ok {
				break
			}
			c.Write(data)
			delete(pending, expect)
			expect++
			m.upExpectSeq[streamID] = expect
		}
		m.upMu.Unlock()
	}
}

func (m *accelManager) pipeUpToClient(streamID uint32, up net.Conn, t *accelTunnel) {
	// read from upstream and send DATA frames to client (downlink)
	fs := m.getFrameSize()
	if fs <= 0 {
		fs = 8192
	}
	buf := make([]byte, fs)
	var seq uint32 = 1
	for {
		n, err := up.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
			// Cache for possible retransmission
			m.downMu.Lock()
			if _, ok := m.downCache[streamID]; !ok {
				m.downCache[streamID] = make(map[uint32][]byte)
				m.downCacheFloor[streamID] = seq
			}
			m.downCache[streamID][seq] = payload
			m.downMu.Unlock()
			// Downlink: duplicate across available tunnels
			m.dupSendFromServer(frame{flags: flagDATA, streamID: streamID, seq: seq, payload: payload}, t)
			seq++
		}
		if err != nil {
			// FIN
			m.dupSendFromServer(frame{flags: flagFIN, streamID: streamID, seq: seq}, t)
			up.Close()
			return
		}
	}
}

func sendOnTunnel(t *accelTunnel, fr frame) error {
	if t == nil || t.conn == nil {
		return fmt.Errorf("no tunnel")
	}
	t.wrMu.Lock()
	defer t.wrMu.Unlock()
	return writeFrame(t.conn, fr)
}

// send frame to multiple tunnels according to current adaptive multiplier
func (m *accelManager) broadcast(fr frame) {
	m.tunMu.RLock()
	tunnels := append([]*accelTunnel(nil), m.tunnels...)
	m.tunMu.RUnlock()
	if len(tunnels) == 0 {
		return
	}
	// choose max dup among tunnels for uplink send fanout
	maxDup := 1
	for _, t := range tunnels {
		d := t.getDup()
		if d > maxDup {
			maxDup = d
		}
	}
	// pick healthiest tunnels first
	sel := selectTopTunnelsByHealth(tunnels, maxDup)
	for _, t := range sel {
		go func(tn *accelTunnel) {
			tn.wrMu.Lock()
			if err := writeFrame(tn.conn, fr); err != nil {
				utils.Logger.Warn("ACC: 写帧失败", zap.Error(err))
			}
			tn.wrMu.Unlock()
			// per-tunnel sent accounting (uplink)
			if fr.flags == flagDATA || fr.flags == flagFIN {
				tn.statMu.Lock()
				tn.sentCount++
				tn.statMu.Unlock()
			}
		}(t)
	}
}

// Downlink send on server side. Primary is the tunnel where upstream was initiated from; we always include it.
func (m *accelManager) dupSendFromServer(fr frame, primary *accelTunnel) {
	m.tunMu.RLock()
	tunnels := append([]*accelTunnel(nil), m.tunnels...)
	m.tunMu.RUnlock()
	if len(tunnels) == 0 {
		return
	}
	// Downlink: follow per-tunnel multiplier as uplink (fanout by max dup among tunnels)
	maxDup := 1
	for _, t := range tunnels {
		d := t.getDup()
		if d > maxDup {
			maxDup = d
		}
	}
	// order by health, ensure primary included
	sel := selectTopTunnelsByHealth(tunnels, maxDup)
	includedPrimary := false
	if primary != nil {
		for _, x := range sel {
			if x == primary {
				includedPrimary = true
				break
			}
		}
		if !includedPrimary {
			// replace last with primary to ensure inclusion
			if len(sel) > 0 {
				sel[len(sel)-1] = primary
			} else {
				sel = append(sel, primary)
			}
		}
	}
	// send
	for _, tn := range sel {
		tn.wrMu.Lock()
		if err := writeFrame(tn.conn, fr); err != nil {
			utils.Logger.Warn("ACC: 写帧失败", zap.Error(err))
		}
		tn.wrMu.Unlock()
	}
}

// selectTopTunnelsByHealth returns top k tunnels ordered by (rttEWMA + jitterEWMA) ascending. Unknown metrics go to the end.
func selectTopTunnelsByHealth(tuns []*accelTunnel, k int) []*accelTunnel {
	if k <= 0 {
		return nil
	}
	// copy
	list := append([]*accelTunnel(nil), tuns...)
	// simple sort by score
	sort.SliceStable(list, func(i, j int) bool {
		si, sj := list[i].score(), list[j].score()
		return si < sj
	})
	if k > len(list) {
		k = len(list)
	}
	return list[:k]
}

func (t *accelTunnel) score() float64 {
	t.statMu.RLock()
	defer t.statMu.RUnlock()
	if t.samples == 0 {
		return 1e9 // no measurement yet, push to end
	}
	return t.rttEWMA + t.jitterEWMA
}

func (t *accelTunnel) updateRTT(rttMs float64) {
	if rttMs <= 0 {
		return
	}
	const alpha = 0.2
	t.statMu.Lock()
	if t.samples == 0 {
		t.rttEWMA = rttMs
		t.jitterEWMA = 0
		t.samples = 1
	} else {
		prev := t.rttEWMA
		t.rttEWMA = alpha*rttMs + (1-alpha)*t.rttEWMA
		diff := rttMs - prev
		if diff < 0 {
			diff = -diff
		}
		t.jitterEWMA = alpha*diff + (1-alpha)*t.jitterEWMA
		t.samples++
	}
	t.statMu.Unlock()
}

// probeTunnel periodically sends PING to measure RTT
func (m *accelManager) probeTunnel(t *accelTunnel) {
	la := config.GlobalCfg.LossAdaptation
	interval := 500 * time.Millisecond
	if la != nil && la.ProbeIntervalMs > 0 {
		interval = time.Duration(la.ProbeIntervalMs) * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	buf := make([]byte, 8)
	for {
		select {
		case <-ticker.C:
			// send PING with timestamp
			now := time.Now().UnixNano()
			binary.BigEndian.PutUint64(buf, uint64(now))
			t.wrMu.Lock()
			if err := writeFrame(t.conn, frame{flags: flagPING, streamID: 0, seq: 0, payload: buf}); err != nil {
				t.wrMu.Unlock()
				return
			}
			t.wrMu.Unlock()
		case <-t.closed:
			return
		}
	}
}

func (m *accelManager) getDuplication() int {
	// Only support adaptive multiplier; when disabled, default to 1
	if config.GlobalCfg.LossAdaptation != nil && config.GlobalCfg.LossAdaptation.Enabled {
		m.statsMu.Lock()
		dup := m.currDup
		m.statsMu.Unlock()
		if dup < 1 {
			dup = 1
		}
		if dup > 5 {
			dup = 5
		}
		return dup
	}
	return 1
}

func (m *accelManager) startAdaptation() {
	la := config.GlobalCfg.LossAdaptation
	if la == nil || !la.Enabled {
		m.statsMu.Lock()
		if m.currDup <= 0 {
			m.currDup = 1
		}
		m.statsMu.Unlock()
		return
	}
	window := time.Duration(la.WindowSeconds) * time.Second
	if window <= 0 {
		window = 10 * time.Second
	}
	ticker := time.NewTicker(window)
	go func() {
		for range ticker.C {
			// iterate per-tunnel and adapt independently
			m.tunMu.RLock()
			list := append([]*accelTunnel(nil), m.tunnels...)
			m.tunMu.RUnlock()
			suggestedFS := 0
			for _, t := range list {
				t.statMu.Lock()
				sent := t.sentCount
				ack := t.ackCount
				t.sentCount = 0
				t.ackCount = 0
				prevDup := t.currDup
				t.statMu.Unlock()
				if sent <= 0 {
					continue
				}
				delivered := float64(ack)
				total := float64(sent)
				loss := 0.0
				if delivered < total {
					loss = (total - delivered) * 100.0 / total
				}
				// select dup by rules (assume ascending lossBelow)
				newDup := 1
				newFS := m.baseFrameSize()
				for _, r := range la.Rules {
					if loss < r.LossBelow {
						newDup = r.Dup
						if r.FrameSize > 0 {
							newFS = r.FrameSize
						}
						break
					}
				}
				if newDup < 1 {
					newDup = 1
				}
				if newDup > 5 {
					newDup = 5
				}
				if newDup != prevDup {
					utils.Logger.Debug("ACC: 自适应倍率更新",
						zap.String("远端", t.peer),
						zap.Float64("丢包率(%)", loss),
						zap.Int("倍率.旧", prevDup),
						zap.Int("倍率.新", newDup),
						zap.Int("窗口发送", sent),
						zap.Int("窗口确认", ack),
						zap.Int("窗口秒", la.WindowSeconds))
				} else {
					utils.Logger.Debug("ACC: 自适应倍率",
						zap.String("远端", t.peer),
						zap.Float64("丢包率(%)", loss),
						zap.Int("倍率", newDup),
						zap.Int("窗口发送", sent),
						zap.Int("窗口确认", ack),
						zap.Int("窗口秒", la.WindowSeconds))
				}
				t.statMu.Lock()
				t.currDup = newDup
				t.statMu.Unlock()

				if newFS > 0 && (suggestedFS == 0 || newFS < suggestedFS) {
					suggestedFS = newFS
				}
			}
			if suggestedFS > 0 {
				m.dynMu.Lock()
				prev := m.dynFrameSize
				if prev <= 0 {
					prev = m.baseFrameSize()
				}
				changed := suggestedFS != prev
				m.dynFrameSize = suggestedFS
				m.dynMu.Unlock()
				if changed {
					utils.Logger.Debug("ACC: 自适应分片大小",
						zap.Int("frameSize.旧", prev),
						zap.Int("frameSize.新", suggestedFS))
				}
			}
		}
	}()
}

// streamConn implements net.Conn over accelerator
type streamConn struct {
	id       uint32
	target   string
	mgr      *accelManager
	readMu   sync.Mutex
	readBuf  [][]byte
	readCond *sync.Cond
	closed   bool
	writeSeq uint32
	readSeq  uint32
	readPend map[uint32][]byte
}

func (m *accelManager) DialTarget(addr string) (net.Conn, error) {
	if m == nil || m.cfg == nil || !m.cfg.Enabled || m.cfg.Role != "client" {
		return nil, fmt.Errorf("accelerator not enabled in client role")
	}
	// ensure at least one tunnel
	m.tunMu.RLock()
	hasTun := len(m.tunnels) > 0
	m.tunMu.RUnlock()
	if !hasTun {
		return nil, fmt.Errorf("no accelerator tunnels available")
	}
	m.streamsMu.Lock()
	m.nextStream++
	id := m.nextStream
	sc := &streamConn{id: id, target: addr, mgr: m, writeSeq: 1, readSeq: 1, readPend: make(map[uint32][]byte)}
	sc.readCond = sync.NewCond(&sc.readMu)
	m.streams[id] = sc
	m.streamsMu.Unlock()

	// send SYN
	m.broadcast(frame{flags: flagSYN, streamID: id, seq: 0, payload: []byte(addr)})

	return sc, nil
}

// DialAccelerated dials addr via accelerator when enabled(client role). Returns (conn, usedAccel, err).
func DialAccelerated(addr string) (net.Conn, bool, error) {
	if gAccel != nil && gAccel.cfg != nil && gAccel.cfg.Enabled && gAccel.cfg.Role == "client" {
		c, err := gAccel.DialTarget(addr)
		if err == nil {
			return c, true, nil
		}
		// fall back to direct
		utils.Logger.Warn("ACC: 回退为直连", zap.String("addr", addr), zap.Error(err))
	}
	c, err := net.Dial("tcp", addr)
	return c, false, err
}

func (sc *streamConn) Read(b []byte) (int, error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()
	for {
		if sc.closed {
			return 0, io.EOF
		}
		if len(sc.readBuf) > 0 {
			chunk := sc.readBuf[0]
			if len(chunk) <= len(b) {
				copy(b, chunk)
				sc.readBuf = sc.readBuf[1:]
				return len(chunk), nil
			}
			copy(b, chunk[:len(b)])
			sc.readBuf[0] = chunk[len(b):]
			return len(b), nil
		}
		sc.readCond.Wait()
	}
}

func (sc *streamConn) Write(b []byte) (int, error) {
	// split into frames
	max := sc.mgr.getFrameSize()
	if max <= 0 {
		max = 8192
	}
	written := 0
	for written < len(b) {
		n := len(b) - written
		if n > max {
			n = max
		}
		payload := make([]byte, n)
		copy(payload, b[written:written+n])
		fr := frame{flags: flagDATA, streamID: sc.id, seq: sc.writeSeq, payload: payload}
		sc.mgr.broadcast(fr)
		sc.writeSeq++
		written += n
	}
	return written, nil
}

// getFrameSize returns current adaptive frame size used for writing frames
func (m *accelManager) getFrameSize() int {
	m.dynMu.RLock()
	fs := m.dynFrameSize
	m.dynMu.RUnlock()
	if fs <= 0 {
		fs = m.baseFrameSize()
	}
	if fs <= 0 {
		fs = 8192
	}
	rm := m.getReadMax()
	if fs > rm {
		fs = rm
	}
	return fs
}

// getReadMax computes a safe max payload length accepted by readFrame
func (m *accelManager) getReadMax() int {
	// start from conservative minimum
	max := 0
	if max < 32768 {
		max = 32768
	}
	la := config.GlobalCfg.LossAdaptation
	if la != nil {
		for _, r := range la.Rules {
			if r.FrameSize > max {
				max = r.FrameSize
			}
		}
	}
	return max
}

// baseFrameSize returns the baseline frame size preference:
// 1) use lossAdaptation rule where dup==1 and frameSize>0, if present
// 2) else default to 32768
func (m *accelManager) baseFrameSize() int {
	la := config.GlobalCfg.LossAdaptation
	if la != nil {
		for _, r := range la.Rules {
			if r.Dup == 1 && r.FrameSize > 0 {
				return r.FrameSize
			}
		}
	}
	return 32768
}

func (sc *streamConn) Close() error {
	if sc.closed {
		return nil
	}
	sc.closed = true
	sc.mgr.broadcast(frame{flags: flagFIN, streamID: sc.id, seq: sc.writeSeq})
	sc.mgr.streamsMu.Lock()
	delete(sc.mgr.streams, sc.id)
	sc.mgr.streamsMu.Unlock()
	sc.readCond.Broadcast()
	return nil
}

func (sc *streamConn) LocalAddr() net.Addr                { return dummyAddr("acc-local") }
func (sc *streamConn) RemoteAddr() net.Addr               { return dummyAddr("acc-remote") }
func (sc *streamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (sc *streamConn) SetWriteDeadline(t time.Time) error { return nil }

// onFrame is called on client-side for incoming frames from server
func (sc *streamConn) onFrame(fr frame) {
	if fr.flags == flagFIN || fr.flags == flagRST {
		sc.Close()
		return
	}
	if fr.flags != flagDATA {
		return
	}
	sc.readMu.Lock()
	// ensure in-order delivery using seq and buffer pending
	if fr.seq == sc.readSeq {
		sc.readBuf = append(sc.readBuf, fr.payload)
		sc.readSeq++
		// flush contiguous pending
		for {
			if p, ok := sc.readPend[sc.readSeq]; ok {
				sc.readBuf = append(sc.readBuf, p)
				delete(sc.readPend, sc.readSeq)
				sc.readSeq++
			} else {
				break
			}
		}
		sc.readCond.Broadcast()
	} else if fr.seq > sc.readSeq {
		// buffer pending higher seq
		if _, exist := sc.readPend[fr.seq]; !exist {
			sc.readPend[fr.seq] = fr.payload
		}
	}
	sc.readMu.Unlock()
}

// server-side write ordering helper
func (m *accelManager) writeInOrderServer(streamID uint32, up net.Conn, seq uint32, payload []byte) {
	m.upMu.Lock()
	expect := m.upExpectSeq[streamID]
	if seq == expect {
		up.Write(payload)
		expect++
		// flush pending contiguous
		if pend, ok := m.upPending[streamID]; ok {
			for {
				if p, ok2 := pend[expect]; ok2 {
					up.Write(p)
					delete(pend, expect)
					expect++
				} else {
					break
				}
			}
		}
		m.upExpectSeq[streamID] = expect
		m.upMu.Unlock()
		return
	}
	if seq > expect {
		if _, ok := m.upPending[streamID]; !ok {
			m.upPending[streamID] = make(map[uint32][]byte)
		}
		if _, exists := m.upPending[streamID][seq]; !exists {
			m.upPending[streamID][seq] = payload
		}
	}
	m.upMu.Unlock()
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

// dialTransport dials a tunnel using configured transport. Currently supports tcp; quic is stubbed to tcp fallback.
func (m *accelManager) dialTransport(remote string) (io.ReadWriteCloser, error) {
	if m.cfg.Transport == "" || m.cfg.Transport == "tcp" {
		c, err := net.Dial("tcp", remote)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	if m.cfg.Transport == "quic" {
		tlsConf := &tls.Config{NextProtos: []string{"moto-accel"}, InsecureSkipVerify: true}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		qc, err := quic.DialAddr(ctx, remote, tlsConf, nil)
		if err != nil {
			return nil, err
		}
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			_ = qc.CloseWithError(0, "open stream failed")
			return nil, err
		}
		return &quicStreamConn{conn: qc, stream: st}, nil
	}
	return nil, fmt.Errorf("unsupported transport: %s", m.cfg.Transport)
}

// QUIC server listener: accept connections and streams, each stream is a tunnel
func (m *accelManager) startServerQUIC() {
	// load server cert if configured, else generate self-signed
	var tlsConf *tls.Config
	if m.cfg.CertificateFile != "" && m.cfg.PrivateKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(m.cfg.CertificateFile, m.cfg.PrivateKeyFile)
		if err != nil {
			utils.Logger.Error("ACC: 加载 TLS 证书/私钥失败，回落到自签名", zap.Error(err))
			tlsConf = generateTLSConfig()
		} else {
			tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"moto-accel"}}
		}
	} else {
		tlsConf = generateTLSConfig()
	}
	ln, err := quic.ListenAddr(m.cfg.Listen, tlsConf, nil)
	if err != nil {
		utils.Logger.Error("ACC: 监听失败 (quic)", zap.String("listen", m.cfg.Listen), zap.Error(err))
		return
	}
	utils.Logger.Info("ACC: 服务器开始监听 (quic)", zap.String("listen", m.cfg.Listen))
	for {
		qc, err := ln.Accept(context.Background())
		if err != nil {
			utils.Logger.Error("ACC: 接受 QUIC 连接失败", zap.Error(err))
			continue
		}
		go func(qc quic.Connection) {
			for {
				st, err := qc.AcceptStream(context.Background())
				if err != nil {
					utils.Logger.Warn("ACC: QUIC 流结束", zap.Error(err))
					return
				}
				t := &accelTunnel{conn: &quicStreamConn{conn: qc, stream: st}, rd: bufio.NewReaderSize(st, 64*1024), closed: make(chan struct{}), peer: qc.RemoteAddr().String()}
				m.tunMu.Lock()
				m.tunnels = append(m.tunnels, t)
				m.tunMu.Unlock()
				utils.Logger.Info("ACC: 服务器隧道已建立 (quic stream)")
				go func(tt *accelTunnel) {
					go m.probeTunnel(tt)
					m.handleTunnelServer(tt)
					// on return, remove
					m.tunMu.Lock()
					for i := range m.tunnels {
						if m.tunnels[i] == tt {
							m.tunnels = append(m.tunnels[:i], m.tunnels[i+1:]...)
							break
						}
					}
					m.tunMu.Unlock()
					utils.Logger.Warn("ACC: 服务器隧道断开 (quic stream)")
				}(t)
			}
		}(qc)
	}
}

type quicStreamConn struct {
	conn   quic.Connection
	stream quic.Stream
}

func (q *quicStreamConn) Read(p []byte) (int, error)  { return q.stream.Read(p) }
func (q *quicStreamConn) Write(p []byte) (int, error) { return q.stream.Write(p) }
func (q *quicStreamConn) Close() error {
	_ = q.stream.Close()
	return q.conn.CloseWithError(0, "closed")
}

// generateTLSConfig creates a self-signed cert for QUIC server
func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"moto"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"moto-accel"}}
}
