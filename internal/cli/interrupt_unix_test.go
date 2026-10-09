//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// lockedBuffer lets the test read what the interrupt goroutine wrote.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Value: protects that the first Ctrl-C names what is being cleaned up and that finishing normally prints nothing; fails_when=the notice is missing after SIGINT or appears after a normal return; why_new=interruptContext is new and the signal path had no test; seam=none
func TestInterruptContext(t *testing.T) {
	t.Run("normal return prints nothing", func(t *testing.T) {
		var out lockedBuffer
		_, stop := interruptContext(&out, "iba")
		stop()
		time.Sleep(50 * time.Millisecond) // give the goroutine its chance to misbehave
		if got := out.String(); got != "" {
			t.Errorf("stderr = %q, want nothing", got)
		}
	})
	t.Run("Ctrl-C names the leftovers", func(t *testing.T) {
		var out lockedBuffer
		ctx, stop := interruptContext(&out, "iba")
		defer stop()
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("ctx was not cancelled by SIGINT")
		}
		deadline := time.Now().Add(2 * time.Second)
		for !strings.Contains(out.String(), "undoing anything created for iba") && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := out.String(); !strings.Contains(got, "undoing anything created for iba") {
			t.Errorf("stderr = %q, want it to name iba", got)
		}
	})
}
