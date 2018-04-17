package ftrace

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	defaultTrimSet = "\r\n\t "
)

func Trim(s string) string {
	return strings.Trim(s, defaultTrimSet)
}

func ReadFileOr(filename string, deflt string) string {
	if data, err := ioutil.ReadFile(filename); err != nil {
		return deflt
	} else {
		return string(data)
	}
}

func WriteFile(filename string, data string) error {
	return ioutil.WriteFile(filename, []byte(data), 0755)
}

func AppendFile(filename string, data string) error {
	fp, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer fp.Close()

	_, err = fp.WriteString(data)
	if err != nil {
		return err
	}
	return nil
}

func Available() bool {
	return Trim(ReadFileOr(EnabledStatusFile, "0")) == "1"
}

func makeDescriptor(name, syscall string) string {
	d := fmt.Sprintf("p:kprobes/%s %s", name, syscall)
	// command line args will be in %si, we're asking ftrace for them
	for argn := 0; argn < MaxArguments; argn++ {
		d += fmt.Sprintf(" arg%d=+0(+%d(%%si)):string", argn, argn*8)
	}
	return d
}

func mapSubevents(subEvents []string) map[string]string {
	m := make(map[string]string)
	if subEvents != nil {
		for _, eventName := range subEvents {
			eventPath := eventName
			// includes a path, like 'sched/sched_process_fork'
			if strings.ContainsRune(eventName, '/') == true {
				parts := strings.SplitN(eventName, "/", 2)
				eventName = parts[1]
			}
			m[eventName] = fmt.Sprintf(EventProbeFileFmt, eventPath)
		}
	}
	return m
}
