package controller

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Simple framed multiplex tunnel with duplication across multiple TCP links.
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
	tunnels    []*accelTunnel
	tunMu      sync.RWMutex
	nextTunIdx int

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
	statsMu   sync.Mutex
	sentCount int // number of frames actually sent (after duplication)
	ackCount  int // number of ACK frames received from peer
	currDup   int // current adaptive duplication (1..5)
}

type accelTunnel struct {
	conn   net.Conn
	rd     *bufio.Reader
	wrMu   sync.Mutex
	closed chan struct{}

	// health metrics
	statMu     sync.RWMutex
	rttEWMA    float64 // ms
	jitterEWMA float64 // ms
	samples    int
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
			cfg:         config.GlobalCfg.Accelerator,
			streams:     make(map[uint32]*streamConn),
			upstreams:   make(map[uint32]net.Conn),
			upExpectSeq: make(map[uint32]uint32),
			upPending:   make(map[uint32]map[uint32][]byte),
		}
		if gAccel.cfg.Role == "client" {
			gAccel.startClient()
			gAccel.startAdaptation()
		} else if gAccel.cfg.Role == "server" {
			go gAccel.startServer()
			gAccel.startAdaptation()
		}
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
				c, err := net.Dial("tcp", m.cfg.Remote)
				if err != nil {
					utils.Logger.Warn("ACC: dial remote failed", zap.String("remote", m.cfg.Remote), zap.Error(err))
					time.Sleep(time.Second)
					continue
				}
				t := &accelTunnel{conn: c, rd: bufio.NewReaderSize(c, 64*1024), closed: make(chan struct{})}
				m.tunMu.Lock()
				m.tunnels = append(m.tunnels, t)
				m.tunMu.Unlock()
				utils.Logger.Info("ACC: tunnel up", zap.String("remote", c.RemoteAddr().String()))
				// start health probing
				go m.probeTunnel(t)
				m.handleTunnelClient(t)
				utils.Logger.Warn("ACC: tunnel down")
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
	ln, err := net.Listen("tcp", m.cfg.Listen)
	if err != nil {
		utils.Logger.Error("ACC: listen failed", zap.String("listen", m.cfg.Listen), zap.Error(err))
		return
	}
	utils.Logger.Info("ACC: server listening", zap.String("listen", m.cfg.Listen))
	for {
		c, err := ln.Accept()
		if err != nil {
			utils.Logger.Error("ACC: accept failed", zap.Error(err))
			time.Sleep(time.Second)
			continue
		}
		t := &accelTunnel{conn: c, rd: bufio.NewReaderSize(c, 64*1024), closed: make(chan struct{})}
		m.tunMu.Lock()
		m.tunnels = append(m.tunnels, t)
		m.tunMu.Unlock()
		utils.Logger.Info("ACC: server tunnel up", zap.String("peer", c.RemoteAddr().String()))
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
			utils.Logger.Warn("ACC: server tunnel down")
		}()
	}
}

// client side tunnel reader: delivers frames to streamConns
func (m *accelManager) handleTunnelClient(t *accelTunnel) {
	max := m.cfg.FrameSize
	if max <= 0 {
		max = 8192
	}
	for {
		fr, err := readFrame(t.rd, max)
		if err != nil {
			close(t.closed)
			return
		}
		// handle ACK for our uplink frames
		if fr.flags == flagACK {
			m.statsMu.Lock()
			m.ackCount++
			m.statsMu.Unlock()
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
		sc.onFrame(fr)
	}
}

// server side tunnel reader: handles SYN/Data for upstreams
func (m *accelManager) handleTunnelServer(t *accelTunnel) {
	max := m.cfg.FrameSize
	if max <= 0 {
		max = 8192
	}
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
		case flagACK:
			// ACK for our downlink frames -> update stats
			m.statsMu.Lock()
			m.ackCount++
			m.statsMu.Unlock()
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
	// read from upstream and send DATA frames to client (duplication)
	buf := make([]byte, m.cfg.FrameSize)
	if len(buf) == 0 {
		buf = make([]byte, 8192)
	}
	var seq uint32 = 1
	for {
		n, err := up.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
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

// send frame to multiple tunnels according to Duplication
func (m *accelManager) broadcast(fr frame) {
	m.tunMu.RLock()
	tunnels := append([]*accelTunnel(nil), m.tunnels...)
	m.tunMu.RUnlock()
	if len(tunnels) == 0 {
		return
	}
	dup := m.getDuplication()
	// pick healthiest tunnels first
	sel := selectTopTunnelsByHealth(tunnels, dup)
	for _, t := range sel {
		go func(tn *accelTunnel) {
			tn.wrMu.Lock()
			_ = writeFrame(tn.conn, fr)
			tn.wrMu.Unlock()
		}(t)
	}
	// sent accounting (uplink duplicates)
	m.statsMu.Lock()
	m.sentCount += len(sel)
	m.statsMu.Unlock()
}

// Downlink duplication on server side. Primary is the tunnel where upstream was initiated from, we always include it.
func (m *accelManager) dupSendFromServer(fr frame, primary *accelTunnel) {
	m.tunMu.RLock()
	tunnels := append([]*accelTunnel(nil), m.tunnels...)
	m.tunMu.RUnlock()
	if len(tunnels) == 0 {
		return
	}
	dup := m.getDuplication()
	// order by health, ensure primary included
	sel := selectTopTunnelsByHealth(tunnels, dup)
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
		_ = writeFrame(tn.conn, fr)
		tn.wrMu.Unlock()
	}
	// sent accounting (downlink duplicates)
	m.statsMu.Lock()
	m.sentCount += len(sel)
	m.statsMu.Unlock()
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
	for {
		select {
		case <-ticker.C:
			// send PING with timestamp
			now := time.Now().UnixNano()
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, uint64(now))
			t.wrMu.Lock()
			_ = writeFrame(t.conn, frame{flags: flagPING, streamID: 0, seq: 0, payload: buf})
			t.wrMu.Unlock()
		case <-t.closed:
			return
		}
	}
}

func (m *accelManager) getDuplication() int {
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
	dup := m.cfg.Duplication
	if dup <= 0 {
		dup = 1
	}
	if dup > 5 {
		dup = 5
	}
	return dup
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
			m.statsMu.Lock()
			sent := m.sentCount
			ack := m.ackCount
			m.sentCount = 0
			m.ackCount = 0
			prevDup := m.currDup
			m.statsMu.Unlock()
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
			for _, r := range la.Rules {
				if loss < r.LossBelow {
					newDup = r.Dup
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
				utils.Logger.Debug("ACC: adapt duplication",
					zap.Float64("loss(%)", loss),
					zap.Int("dup.prev", prevDup),
					zap.Int("dup.new", newDup),
					zap.Int("sent", sent),
					zap.Int("ack", ack),
					zap.Int("windowSeconds", la.WindowSeconds))
			} else {
				// periodic debug even when unchanged
				utils.Logger.Debug("ACC: adapt tick",
					zap.Float64("loss(%)", loss),
					zap.Int("dup", newDup),
					zap.Int("sent", sent),
					zap.Int("ack", ack),
					zap.Int("windowSeconds", la.WindowSeconds))
			}
			m.statsMu.Lock()
			m.currDup = newDup
			m.statsMu.Unlock()
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
		utils.Logger.Warn("ACC: fallback to direct dial", zap.String("addr", addr), zap.Error(err))
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
	max := sc.mgr.cfg.FrameSize
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
