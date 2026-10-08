package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

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
	fmt.Fprint(p.out, label)
	if !p.in.Scan() {
		fmt.Fprintln(p.out)
		if err := p.in.Err(); err != nil {
			return "", err
		}
		return "", errNoInput
	}
	return strings.TrimSpace(p.in.Text()), nil
}

// secret is like line, but doesn't echo what's typed when stdin is a terminal.
func (p *prompter) secret(label string) (string, error) {
	if p.fd < 0 {
		return p.line(label)
	}
	fmt.Fprint(p.out, label)
	b, err := term.ReadPassword(p.fd)
	fmt.Fprintln(p.out) // the Enter key wasn't echoed either
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
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
