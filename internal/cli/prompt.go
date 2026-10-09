package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"
)

// exitInterrupted is the exit code for a command stopped by Ctrl-C (128 + SIGINT).
const exitInterrupted = 130

// prompter reads answers from stdin. Every prompt in a command must go
// through the same prompter: bufio.Scanner reads ahead, so a second scanner
// on the same stdin could find its input already swallowed by the first.
type prompter struct {
	in  *bufio.Scanner
	out io.Writer
	tty *os.File // stdin if it's a terminal, otherwise nil
	fd  int      // tty's file descriptor, or -1
}

func newPrompter(stdin io.Reader, out io.Writer) *prompter {
	p := &prompter{in: bufio.NewScanner(stdin), out: out, fd: -1}
	// A type assertion: is this io.Reader really an *os.File underneath?
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		p.tty, p.fd = f, int(f.Fd())
	}
	return p
}

// errNoInput means stdin ended before an answer was given.
var errNoInput = errors.New("no input")

// line prints label and returns the next line of input, trimmed.
func (p *prompter) line(label string) (string, error) {
	answer, err := p.rawLine(label)
	return strings.TrimSpace(answer), err
}

// rawLine is like line, but keeps spaces at either end.
func (p *prompter) rawLine(label string) (string, error) {
	fmt.Fprint(p.out, label)
	if !p.in.Scan() {
		fmt.Fprintln(p.out)
		if err := p.in.Err(); err != nil {
			return "", err
		}
		return "", errNoInput
	}
	return p.in.Text(), nil
}

// secret is like rawLine, but doesn't echo what's typed when stdin is a
// terminal. It doesn't trim either: spaces can be part of a password.
func (p *prompter) secret(label string) (string, error) {
	if p.fd < 0 {
		return p.rawLine(label)
	}
	old, err := term.GetState(p.fd)
	if err != nil {
		return "", err
	}
	// ReadPassword turns echo off until it returns. Ctrl-C arrives as SIGINT and
	// would end the process first, leaving the shell with echo off. So catch it
	// here, put the terminal back, and exit the way an interrupted command does.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupts:
			term.Restore(p.fd, old)
			fmt.Fprintln(p.out)
			os.Exit(exitInterrupted)
		case <-done:
		}
	}()

	fmt.Fprint(p.out, label)
	b, err := term.ReadPassword(p.fd)
	fmt.Fprintln(p.out) // the Enter key wasn't echoed either
	if errors.Is(err, io.EOF) {
		return "", errNoInput // Ctrl-D: the same as the end of piped input
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ask prompts until validate accepts the answer. An empty answer means def,
// if def isn't empty. what names the answer in errors ("project name").
func (p *prompter) ask(label, what, def string, validate func(string) error) (string, error) {
	if def != "" {
		label = fmt.Sprintf("%s [%s]: ", label, def)
	} else {
		label += ": "
	}
	for {
		answer, err := p.line(label)
		if errors.Is(err, errNoInput) {
			return "", fmt.Errorf("no %s given", what)
		}
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", what, err)
		}
		if answer == "" {
			answer = def
		}
		err = validate(answer)
		if err == nil {
			return answer, nil
		}
		fmt.Fprintln(p.out, err)
	}
}
