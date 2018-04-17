package ftrace

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var eventParser = regexp.MustCompile(`^.+\-(\d+)\s+\[\d+\].+:\s+([^:]+):\s+(.+)$`)

// Event represents a single FTRACE notification.
type Event struct {
	// process id for this event
	PID int
	// name of this event
	Name string
	// true if this is a syscall event or false of any sub event
	IsSyscall bool
	// argv if this is a syscall, otherwise just the event's data map
	Args map[string]string
}

// Argv returns a list of the argument values of this event.
func (e Event) Argv() []string {
	nargs := len(e.Args)
	argv := make([]string, nargs)

	// maps are not sorted
	if e.IsSyscall {
		for i := 0; i < nargs; i++ {
			argv[i] = e.Args[fmt.Sprintf("arg%d", i)]
		}
	} else {
		argc := 0
		for _, v := range e.Args {
			argv[argc] = v
			argc++
		}
	}
	return argv
}

// String returns a string representation of this event.
func (e Event) String() string {
	s := fmt.Sprintf("pid:%d %s", e.PID, e.Name)
	if e.IsSyscall {
		s += fmt.Sprintf("(%s)", strings.Join(e.Argv(), ", "))
	} else {
		s += fmt.Sprintf(" -> %s", e.Args)
	}
	return s
}

func parseUntilNext(data string, tok rune) (string, int) {
	tokOffset := strings.IndexRune(data, tok)
	if tokOffset == -1 {
		return "", -1
	}

	return data[0:tokOffset], tokOffset
}

func parseEvent(data string) (Event, error) {
	m := eventParser.FindStringSubmatch(trim(data))
	if m != nil && len(m) == 4 {
		pid, _ := strconv.Atoi(m[1])
		event := Event{
			PID:       pid,
			Name:      m[2],
			IsSyscall: len(m[3]) > 0 && m[3][0] == '(',
			Args:      make(map[string]string),
		}

		args := m[3]
		if event.IsSyscall {
			// remove the syscall name from the arguments
			nameEndOffset := strings.Index(args, ") ")
			event.Name = args[1:nameEndOffset]
			args = args[nameEndOffset+2:]
			// remove extra crap aftr the + ( "SyS_execve+0x0/0x40" )
			if strings.ContainsRune(event.Name, '+') {
				parts := strings.SplitN(event.Name, "+", 2)
				event.Name = trim(parts[0])
			}
		}

		for len(args) > 0 {
			eqOffset := strings.IndexRune(args, '=')
			if eqOffset == -1 {
				break
			}

			argName := args[0:eqOffset]
			argValue := ""
			offset := -1

			args = args[eqOffset+1:]

			if args[0] == '"' {
				if argValue, offset = parseUntilNext(args[1:], '"'); offset == -1 {
					break
				}
				args = args[offset+3:]
			} else {
				if argValue, offset = parseUntilNext(args, ' '); offset == -1 {
					break
				}
				args = args[offset+1:]
			}

			// no more arguments for this syscall
			if argValue == "(fault)" {
				break
			}

			event.Args[argName] = argValue
		}

		return event, nil
	}

	return Event{}, fmt.Errorf("Could not parse event data '%s'", data)
}
