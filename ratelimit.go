package main

import (
	"sync"
	"time"
)

// RateLimiter — токен-бакетограничитель для защиты от UDP-флуда.
//
// Принцип работы:
// - Каждому ключу (IP-адресу) соответствует свой бакет с токенами
// - Токены добавляются с фиксированной скоростью (rate)
// - При обработке пакета один токен расходуется
// - Если токенов нет — пакет отбрасывается
// - Burst определяет максимальный размер бакета (разрешённый всплеск)
//
// Это защищает от:
// - UDP spoofing flood (один IP отправляет тысячи пакетов в секунду)
// - Broadcast storms (узел генерирует чрезмерный трафик обнаружения)
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // токенов в секунду
	burst   int     // максимальный размер бакета
	cleanup time.Duration
	stopCh  chan struct{}
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// NewRateLimiter создаёт новый rate limiter.
// rate — средняя скорость (токенов/сек), burst — максимальный размер всплеска.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
		cleanup: 60 * time.Second,
		stopCh:  make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Allow проверяет, разрешён ли пакет от данного ключа (обычно IP).
// Возвращает true если токен доступен, false если превышен лимит.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	bucket, exists := rl.buckets[key]
	if !exists {
		rl.buckets[key] = &tokenBucket{
			tokens:   float64(rl.burst) - 1, // первый пакет всегда проходит
			lastTime: now,
		}
		return true
	}

	// Пополняем бакет пропорционально прошедшему времени
	elapsed := now.Sub(bucket.lastTime).Seconds()
	bucket.tokens += elapsed * rl.rate
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}
	bucket.lastTime = now

	if bucket.tokens < 1.0 {
		return false // токенов нет — отбрасываем пакет
	}

	bucket.tokens -= 1.0
	return true
}

// cleanupLoop периодически удаляет неактивные бакеты,
// чтобы не утекала память при большом количестве уникальных IP.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, bucket := range rl.buckets {
				// Удаляем бакеты, не использовавшиеся более 2 минут
				if now.Sub(bucket.lastTime) > 2*time.Minute {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Stop останавливает фоновую очистку.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// Stats возвращает количество активных бакетов (для мониторинга).
func (rl *RateLimiter) Stats() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}
