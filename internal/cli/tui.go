package cli

// Two small interactive widgets: an arrow-key menu and a text field with a
// fixed prefix. They put the terminal in raw mode, where it passes on every
// key press immediately instead of a line at a time and doesn't echo
// anything, so all drawing is done here with ANSI escape codes. Without a
// terminal, both fall back to plain line prompts.

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/term"
)

// ANSI escape codes.
const (
	clearLine  = "\r\x1b[K" // to column 0, erase the line
	clearBelow = "\x1b[J"   // erase from the cursor to the end of the screen
	hideCursor = "\x1b[?25l"
	showCursor = "\x1b[?25h"
	bold       = "\x1b[1m"
	dim        = "\x1b[2m"
	reset      = "\x1b[0m"
	bell       = "\a"
)

func cursorUp(n int) string { return fmt.Sprintf("\x1b[%dA", n) }

var errInterrupted = errors.New("interrupted")

type key int

const (
	keyOther key = iota
	keyUp
	keyDown
	keyEnter
	keyBackspace
	keyClear     // Ctrl-U
	keyInterrupt // Ctrl-C or Ctrl-D
	keyText      // a printable character
)

type keyPress struct {
	key key
	ch  byte // for keyText
}

// readKeys waits for input and splits it into key presses. One Read can hold
// several: a pasted string, a burst of backspaces from holding the key down,
// or an escape sequence such as ESC [ A for the up arrow.
func (p *prompter) readKeys() ([]keyPress, error) {
	buf := make([]byte, 256)
	n, err := p.tty.Read(buf)
	if err != nil {
		return nil, err
	}
	b := buf[:n]

	var keys []keyPress
	for len(b) > 0 {
		c := b[0]
		switch {
		case c == 0x1b && len(b) >= 2 && b[1] == '[':
			// A CSI sequence: ESC [, then parameter bytes (0x30-0x3F) such as "1;5"
			// and intermediate bytes (0x20-0x2F), then one final byte (0x40-0x7E).
			// Ctrl-Up is ESC [ 1 ; 5 A. Any other byte ends the sequence early
			// without being consumed, so ESC [ followed by Enter still gets Enter.
			end := 2
			for end < len(b) && b[end] >= 0x20 && b[end] <= 0x3f {
				end++
			}
			if end == len(b) {
				b = nil // incomplete sequence at the end of this read: drop the rest
				continue
			}
			if b[end] < 0x40 || b[end] > 0x7e {
				b = b[end:] // malformed: drop ESC [ and its parameters, keep the rest
				continue
			}
			switch b[end] {
			case 'A':
				keys = append(keys, keyPress{key: keyUp})
			case 'B':
				keys = append(keys, keyPress{key: keyDown})
			}
			b = b[end+1:]
			continue
		case c == '\r' || c == '\n':
			keys = append(keys, keyPress{key: keyEnter})
		case c == 0x7f || c == 0x08:
			keys = append(keys, keyPress{key: keyBackspace})
		case c == 0x15:
			keys = append(keys, keyPress{key: keyClear})
		case c == 0x03 || c == 0x04:
			// Raw mode turns off the terminal's signal handling, so Ctrl-C
			// arrives as a plain byte instead of interrupting the process.
			keys = append(keys, keyPress{key: keyInterrupt})
		case c >= 0x20 && c < 0x7f:
			keys = append(keys, keyPress{key: keyText, ch: c})
		default:
			keys = append(keys, keyPress{key: keyOther})
		}
		b = b[1:]
	}
	return keys, nil
}

// rawMode runs fn with the terminal in raw mode and restores it afterwards,
// even if fn fails.
func (p *prompter) rawMode(fn func() error) error {
	old, err := term.MakeRaw(p.fd)
	if err != nil {
		return err
	}
	defer term.Restore(p.fd, old)
	return fn()
}

type choice struct {
	key   string // what to type when there's no terminal
	label string
	desc  string
}

// choose lets the user pick one of choices and returns its index. The first
// choice is the default.
func (p *prompter) choose(label string, choices []choice) (int, error) {
	if p.fd < 0 {
		return p.chooseLine(label, choices)
	}

	width := 0
	for _, c := range choices {
		width = max(width, len(c.label))
	}
	sel := 0
	draw := func() {
		for i, c := range choices {
			if i == sel {
				fmt.Fprintf(p.out, "%s%s> %-*s%s  %s\r\n", clearLine, bold, width, c.label, reset, c.desc)
			} else {
				fmt.Fprintf(p.out, "%s  %-*s  %s%s%s\r\n", clearLine, width, c.label, dim, c.desc, reset)
			}
		}
	}

	err := p.rawMode(func() error {
		fmt.Fprint(p.out, hideCursor)
		defer fmt.Fprint(p.out, showCursor)

		// In raw mode "\n" only moves down; "\r" is needed to get back to
		// column 0.
		fmt.Fprintf(p.out, "%s %s(↑/↓, Enter)%s\r\n", label, dim, reset)
		draw()
		for {
			keys, err := p.readKeys()
			if err != nil {
				return err
			}
			for _, k := range keys {
				switch k.key {
				case keyUp:
					sel = (sel + len(choices) - 1) % len(choices)
				case keyDown:
					sel = (sel + 1) % len(choices)
				case keyEnter:
					// Replace the menu with a one-line summary of the answer.
					fmt.Fprint(p.out, cursorUp(len(choices)+1), clearLine, clearBelow)
					fmt.Fprintf(p.out, "%s: %s\r\n", label, choices[sel].label)
					return nil
				case keyInterrupt:
					return errInterrupted
				}
			}
			fmt.Fprint(p.out, cursorUp(len(choices)))
			draw()
		}
	})
	return sel, err
}

func (p *prompter) chooseLine(label string, choices []choice) (int, error) {
	keys := make([]string, len(choices))
	for i, c := range choices {
		keys[i] = c.key
	}
	answer, err := p.ask(fmt.Sprintf("%s (%s)", label, strings.Join(keys, ", ")), strings.ToLower(label), choices[0].key,
		func(a string) error {
			for _, k := range keys {
				if a == k {
					return nil
				}
			}
			return fmt.Errorf("answer one of: %s", strings.Join(keys, ", "))
		})
	if err != nil {
		return 0, err
	}
	for i, k := range keys {
		if answer == k {
			return i, nil
		}
	}
	panic("unreachable: ask only returns validated answers")
}

// prefixed asks for a name that must start with prefix. Only the part after
// the prefix can be edited; it starts out as def. Characters for which allowed
// returns false are refused, and so is anything that would make the whole
// name longer than maxLen.
func (p *prompter) prefixed(label, prefix, def string, maxLen int, allowed func(byte) bool) (string, error) {
	if p.fd < 0 {
		return p.prefixedLine(label, prefix, def, maxLen, allowed)
	}

	suffix := []byte(def)
	draw := func() {
		fmt.Fprintf(p.out, "%s%s: %s%s%s%s", clearLine, label, dim, prefix, reset, suffix)
	}

	err := p.rawMode(func() error {
		draw()
		for {
			keys, err := p.readKeys()
			if err != nil {
				return err
			}
			for _, k := range keys {
				switch k.key {
				case keyText:
					if !allowed(k.ch) || len(prefix)+len(suffix) >= maxLen {
						fmt.Fprint(p.out, bell)
						continue
					}
					suffix = append(suffix, k.ch)
				case keyBackspace:
					if len(suffix) == 0 {
						fmt.Fprint(p.out, bell) // the prefix can't be deleted
						continue
					}
					suffix = suffix[:len(suffix)-1]
				case keyClear:
					suffix = suffix[:0]
				case keyEnter:
					if len(suffix) == 0 {
						fmt.Fprint(p.out, bell)
						continue
					}
					draw()
					fmt.Fprint(p.out, "\r\n")
					return nil
				case keyInterrupt:
					fmt.Fprint(p.out, "\r\n")
					return errInterrupted
				}
			}
			draw()
		}
	})
	return prefix + string(suffix), err
}

func (p *prompter) prefixedLine(label, prefix, def string, maxLen int, allowed func(byte) bool) (string, error) {
	suffix, err := p.ask(label+": "+prefix, strings.ToLower(label), def, func(s string) error {
		switch {
		case s == "":
			return fmt.Errorf("type at least one character after %s", prefix)
		case len(prefix)+len(s) > maxLen:
			return fmt.Errorf("%s%s is %d characters long; the maximum is %d", prefix, s, len(prefix)+len(s), maxLen)
		}
		for i := 0; i < len(s); i++ {
			if !allowed(s[i]) {
				return fmt.Errorf("%q isn't allowed; use lowercase letters, digits and underscores", s[i])
			}
		}
		return nil
	})
	return prefix + suffix, err
}
