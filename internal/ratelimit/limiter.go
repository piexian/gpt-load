// Package ratelimit provides per-channel and per-key rate limiting.
package ratelimit

import (
	"errors"
	"fmt"
	"time"

	"gpt-load/internal/store"
	"gpt-load/internal/types"
)

// ErrRateLimitExceeded is returned when a channel-level rate limit is exceeded.
var ErrRateLimitExceeded = errors.New("rate limit exceeded")

// RateLimiter checks and records request counters for RPM and daily limits.
type RateLimiter struct {
	store store.Store
}

// New creates a new RateLimiter backed by the given store.
func New(s store.Store) *RateLimiter {
	return &RateLimiter{store: s}
}

// CheckChannel checks the channel-level rate limit and increments the counter.
// Returns ErrRateLimitExceeded when the channel has exceeded its configured limit.
// On failure, call RollbackChannel to restore the counters.
func (r *RateLimiter) CheckChannel(groupID uint, cfg types.SystemSettings) error {
	if cfg.RpmLimit > 0 {
		key := fmt.Sprintf("rl:ch:%d:rpm:%d", groupID, currentMinuteBucket())
		val, err := r.store.IncrWithTTL(key, 120*time.Second)
		if err != nil {
			return nil // fail open
		}
		if val > int64(cfg.RpmLimit) {
			r.store.DecrCounter(key)
			return ErrRateLimitExceeded
		}
	}

	if cfg.DailyLimit > 0 {
		key := fmt.Sprintf("rl:ch:%d:daily:%s", groupID, dailyPeriodKey(cfg.DailyResetHour))
		val, err := r.store.IncrWithTTL(key, 26*time.Hour)
		if err != nil {
			return nil
		}
		if val > int64(cfg.DailyLimit) {
			r.store.DecrCounter(key)
			return ErrRateLimitExceeded
		}
	}

	return nil
}

// RollbackChannel decrements the channel-level counters after a failed request.
func (r *RateLimiter) RollbackChannel(groupID uint, cfg types.SystemSettings) {
	if cfg.RpmLimit > 0 {
		key := fmt.Sprintf("rl:ch:%d:rpm:%d", groupID, currentMinuteBucket())
		r.store.DecrCounter(key)
	}
	if cfg.DailyLimit > 0 {
		key := fmt.Sprintf("rl:ch:%d:daily:%s", groupID, dailyPeriodKey(cfg.DailyResetHour))
		r.store.DecrCounter(key)
	}
}

// CheckKey checks the key-level rate limit and increments the counter.
// Returns (true, nil) when the key has exceeded its configured limit.
// On failure, call RollbackKey to restore the counters.
func (r *RateLimiter) CheckKey(keyID uint, cfg types.SystemSettings) (bool, error) {
	if cfg.RpmLimit > 0 {
		key := fmt.Sprintf("rl:key:%d:rpm:%d", keyID, currentMinuteBucket())
		val, err := r.store.IncrWithTTL(key, 120*time.Second)
		if err != nil {
			return false, nil
		}
		if val > int64(cfg.RpmLimit) {
			r.store.DecrCounter(key)
			return true, nil
		}
	}

	if cfg.DailyLimit > 0 {
		key := fmt.Sprintf("rl:key:%d:daily:%s", keyID, dailyPeriodKey(cfg.DailyResetHour))
		val, err := r.store.IncrWithTTL(key, 26*time.Hour)
		if err != nil {
			return false, nil
		}
		if val > int64(cfg.DailyLimit) {
			r.store.DecrCounter(key)
			return true, nil
		}
	}

	return false, nil
}

// RollbackKey decrements the key-level counters after a failed request.
func (r *RateLimiter) RollbackKey(keyID uint, cfg types.SystemSettings) {
	if cfg.RpmLimit > 0 {
		key := fmt.Sprintf("rl:key:%d:rpm:%d", keyID, currentMinuteBucket())
		r.store.DecrCounter(key)
	}
	if cfg.DailyLimit > 0 {
		key := fmt.Sprintf("rl:key:%d:daily:%s", keyID, dailyPeriodKey(cfg.DailyResetHour))
		r.store.DecrCounter(key)
	}
}

// currentMinuteBucket returns an integer that uniquely identifies the current
// calendar minute (Unix timestamp divided by 60).
func currentMinuteBucket() int64 {
	return time.Now().Unix() / 60
}

// dailyPeriodKey returns a string key that identifies the current "billing day"
// relative to the configured reset hour.
//
// Example: resetHour=8 means the day resets at 08:00 local time.
// At 07:59 the key still belongs to the previous day; at 08:00 it rolls over.
func dailyPeriodKey(resetHour int) string {
	now := time.Now()
	shifted := now.Add(-time.Duration(resetHour) * time.Hour)
	return shifted.Format("20060102")
}
