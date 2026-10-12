package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestParsePTYReq — разбор запроса PTY.
//
// Значения приходят по сети, поэтому важна не только happy path: обрезанный
// payload обязан давать nil, а не падать и не читать за границей буфера.
// Прежде bounds-проверка стояла только в обработчике exec-запросов (дефект 11
// диагностики), а разбор PTY остался без неё.
func TestParsePTYReq(t *testing.T) {
	// "xterm-256color" (14 байт), 120x40, далее modes — 8 нулевых байт.
	payload := []byte{
		0, 0, 0, 14,
		'x', 't', 'e', 'r', 'm', '-', '2', '5', '6', 'c', 'o', 'l', 'o', 'r',
		0, 0, 0, 120,
		0, 0, 0, 40,
		0, 0, 0, 0, 0, 0, 0, 0,
	}

	pty := parsePTYReq(payload)
	if pty == nil {
		t.Fatal("корректный запрос PTY должен разбираться")
	}
	if pty.Term != "xterm-256color" {
		t.Fatalf("терминал: %q", pty.Term)
	}
	if pty.Width != 120 || pty.Height != 40 {
		t.Fatalf("размер: %dx%d, ожидалось 120x40", pty.Width, pty.Height)
	}

	// Обрезки по всем границам.
	for _, bad := range [][]byte{
		nil,
		{0, 0, 0},
		{0, 0, 0, 12, 'x'},
		{0, 0, 0, 12, 'x', 't', 'e', 'r', 'm', '-', '2', '5', '6', 'c', 'o', 'l'},
		// длина имени больше, чем данных, — классическая попытка переполнения
		{0xFF, 0xFF, 0xFF, 0xFF},
	} {
		if got := parsePTYReq(bad); got != nil {
			t.Fatalf("обрезанный payload %v не должен разбираться, получено %+v", bad, got)
		}
	}
}

// TestParseWinChange — разбор window-change.
func TestParseWinChange(t *testing.T) {
	w, h := parseWinChange([]byte{0, 0, 1, 44, 0, 0, 0, 100})
	if w != 300 || h != 100 {
		t.Fatalf("размер: %dx%d, ожидалось 300x100", w, h)
	}

	// Обрезанный payload даёт размер по умолчанию, а не мусор.
	for _, bad := range [][]byte{nil, {1}, {0, 0, 0, 80, 0, 0}} {
		w, h := parseWinChange(bad)
		if w != 80 || h != 24 {
			t.Fatalf("обрезанный payload %v: получено %dx%d, ожидалось 80x24", bad, w, h)
		}
	}
}

// TestParseSignal — разбор имени сигнала.
func TestParseSignal(t *testing.T) {
	if got := parseSignal([]byte{0, 0, 0, 4, 'K', 'I', 'L', 'L'}); got != "KILL" {
		t.Fatalf("сигнал: %q, ожидалось KILL", got)
	}

	for _, bad := range [][]byte{
		nil,
		{0, 0, 0},
		{0, 0, 0, 9, 'K', 'I', 'L', 'L'}, // длина больше данных
	} {
		if got := parseSignal(bad); got != "" {
			t.Fatalf("обрезанный payload %v не должен разбираться, получено %q", bad, got)
		}
	}
}

// fakeChannel — заглушка ssh.Channel: нужно только закрытие, которое
// вызывает watchdog при простое.
type fakeChannel struct {
	ssh.Channel

	mu     sync.Mutex
	closed bool
}

func (f *fakeChannel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeChannel) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// TestIdleWatcherResetsOnActivity — watchdog продлевается активностью клиента.
//
// Прежде таймер не сбрасывался, и сессия умирала ровно через 10 минут даже при
// непрерывной работе.
func TestIdleWatcherResetsOnActivity(t *testing.T) {
	s := &SSHServer{config: DefaultConfig(), idleTimeout: 200 * time.Millisecond}

	ch := &fakeChannel{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reset := s.idleWatcher(ctx, ch)

	// Каждую половину таймаута имитируем активность клиента: без сброса
	// watchdog закрыл бы соединение примерно через 200 мс.
	for i := 0; i < 6; i++ {
		time.Sleep(100 * time.Millisecond)
		select {
		case reset <- struct{}{}:
		default:
		}
	}

	if ch.isClosed() {
		t.Fatal("watchdog закрыл соединение при непрерывной активности")
	}

	// Теперь клиент замолчал — соединение должно закрыться.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !ch.isClosed() {
		time.Sleep(20 * time.Millisecond)
	}

	if !ch.isClosed() {
		t.Fatal("watchdog не закрыл соединение после простоя")
	}
}

// TestResetIdleResetsTimer — сброс таймера продлевает его, а не создаёт новый.
func TestResetIdleResetsTimer(t *testing.T) {
	s := &SSHServer{config: DefaultConfig(), idleTimeout: 300 * time.Millisecond}

	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()

	s.ResetIdle(timer)

	select {
	case <-timer.C:
		t.Fatal("таймер не продлён: сработал по старому сроку")
	case <-time.After(150 * time.Millisecond):
	}
}
