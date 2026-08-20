package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// ReloadRules validates and atomically publishes a new immutable rule
// generation. Existing connections continue with their previous generation;
// connections accepted after the commit use only the new one.
func (s *Server) ReloadRules(ctx context.Context, rules []*config.Rule) (ReloadResult, error) {
	if s == nil {
		return ReloadResult{}, errors.New("server is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	listenerKeys := make([]string, len(rules))
	for index, rule := range rules {
		if rule == nil {
			return ReloadResult{}, fmt.Errorf("rules[%d]: rule is null", index)
		}
		if endpointPortIsZero(rule.Listen) {
			return ReloadResult{}, fmt.Errorf("rules[%d]: reload does not support ephemeral listen address %q", index, rule.Listen)
		}
		listenerKeys[index] = rule.Listen
	}

	old := s.current.Load()
	if old == nil {
		return ReloadResult{}, errors.New("server has no active routing generation")
	}
	nextID := old.id + 1
	if nextID <= old.id {
		return ReloadResult{}, errors.New("routing generation counter overflow")
	}
	next, err := newRoutingGeneration(nextID, rules, listenerKeys, s.prewarmDialSem)
	if err != nil {
		return ReloadResult{}, fmt.Errorf("prepare reload: %w", err)
	}
	result := ReloadResult{FromGeneration: old.id, ToGeneration: next.id}
	if next.fingerprint == old.fingerprint {
		next.retire()
		result.ToGeneration = old.id
		result.Noop = true
		return result, nil
	}
	if s.retiredCount() >= maxRetiredGenerations {
		next.retire()
		return ReloadResult{}, fmt.Errorf("reload rejected: %d routing generations are still draining", maxRetiredGenerations)
	}

	s.lifecycleMu.Lock()
	existing := make(map[string]*listenerState, len(s.listenersByKey))
	for key, state := range s.listenersByKey {
		existing[key] = state
	}
	admissions := make(map[string]*listenerAdmission, len(s.admissionsByKey))
	for key, admission := range s.admissionsByKey {
		admissions[key] = admission
	}
	closed := s.closed
	s.lifecycleMu.Unlock()
	if closed {
		next.retire()
		return ReloadResult{}, errors.New("server is closed")
	}

	staged := make(map[string]*listenerState)
	closeStaged := func() {
		for _, state := range staged {
			_ = state.listener.Close()
		}
	}
	for _, key := range listenerKeys {
		if _, reused := existing[key]; reused {
			result.Reused = append(result.Reused, key)
			continue
		}
		listener, listenErr := (&net.ListenConfig{}).Listen(ctx, "tcp", key)
		if listenErr != nil {
			closeStaged()
			next.retire()
			return ReloadResult{}, fmt.Errorf("stage listener %q: %w", key, listenErr)
		}
		admission := admissions[key]
		if admission == nil {
			admission = &listenerAdmission{perIP: make(map[netip.Addr]int)}
		}
		state := &listenerState{
			key:       key,
			listener:  listener,
			admission: admission,
		}
		staged[key] = state
		result.Added = append(result.Added, key)
	}
	for key := range existing {
		if _, keep := next.bindings[key]; !keep {
			result.Removed = append(result.Removed, key)
		}
	}
	if err := ctx.Err(); err != nil {
		closeStaged()
		next.retire()
		return ReloadResult{}, fmt.Errorf("reload cancelled before commit: %w", err)
	}

	s.lifecycleMu.Lock()
	if err := ctx.Err(); err != nil {
		s.lifecycleMu.Unlock()
		closeStaged()
		next.retire()
		return ReloadResult{}, fmt.Errorf("reload cancelled before commit: %w", err)
	}
	if s.closed {
		s.lifecycleMu.Unlock()
		closeStaged()
		next.retire()
		return ReloadResult{}, errors.New("server closed before reload commit")
	}
	if s.current.Load() != old {
		s.lifecycleMu.Unlock()
		closeStaged()
		next.retire()
		return ReloadResult{}, errors.New("routing generation changed during reload")
	}
	for key, state := range staged {
		s.listenersByKey[key] = state
		s.admissionsByKey[key] = state.admission
		s.listeners = append(s.listeners, state)
	}

	// This store is the only commit point. Nothing after it can fail in a way
	// that requires publishing the old generation again.
	s.current.Store(next)
	if s.serveStarted {
		next.startBackground()
		for _, state := range staged {
			s.startListenerLocked(state)
		}
	}
	for _, key := range result.Removed {
		if state := s.listenersByKey[key]; state != nil {
			_ = state.listener.Close()
			delete(s.listenersByKey, key)
		}
	}
	kept := s.listeners[:0]
	for _, state := range s.listeners {
		if _, ok := s.listenersByKey[state.key]; ok {
			kept = append(kept, state)
		}
	}
	s.listeners = kept
	s.trackRetired(old)
	s.lifecycleMu.Unlock()

	old.retire()
	sort.Strings(result.Added)
	sort.Strings(result.Reused)
	sort.Strings(result.Removed)
	return result, nil
}

// Generation reports the currently published immutable routing generation.
// It is primarily useful for operational logging and tests.
func (s *Server) Generation() uint64 {
	if s == nil {
		return 0
	}
	if generation := s.current.Load(); generation != nil {
		return generation.id
	}
	return 0
}

func endpointPortIsZero(value string) bool {
	_, portText, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port == 0
}
