package ftrace

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

var ErrUnavailable = errors.New("FTRACE kernel framework not available on your system")

type Probe struct {
	sync.RWMutex
	// custom name of the probe
	name string
	// probe status file name
	fileName string
	// syscall to intercept
	syscall string
	// ftrace descriptor of the probe
	descriptor string
	// kernel sub events
	events map[string]string
	// probe status
	enabled bool
	// pipe file reader
	pipe chan string
	// channel used to signal from the worker
	done chan bool
	// channel where events are sent
	bus chan string
}

func NewProbe(name string, syscall string, subEvents []string) *Probe {
	return &Probe{
		name:       name,
		fileName:   fmt.Sprintf(ProbeFileFmt, name),
		syscall:    syscall,
		descriptor: makeDescriptor(name, syscall),
		events:     mapSubevents(subEvents),
		enabled:    false,
		pipe:       nil,
		done:       make(chan bool),
		bus:        make(chan string),
	}
}

func (this *Probe) Enabled() bool {
	this.RLock()
	defer this.RUnlock()
	return this.enabled
}

func (this *Probe) Events() <-chan string {
	return this.bus
}

func (this *Probe) selectEvent(event string) bool {
	// main probe event
	if strings.Contains(event, this.name) {
		return true
	}
	// one of the sub events
	for eventName, _ := range this.events {
		if strings.Contains(event, eventName) {
			return true
		}
	}
	return false
}

func (this *Probe) worker() {
	// signal we're done when we exit
	defer func() {
		this.done <- true
	}()

	for eventLine := range this.pipe {
		if eventLine == "<quit>" {
			break
		}

		/*
			             vim-5232  [001] d... 11412.940204: test_probe: (SyS_execve+0x0/0x40) arg0="/usr/bin/zsh" arg1="-c" arg2="(git -c color.status=false status -s /home/evilsocket/gocode/src/github.com/evilsocket/ftrace) >/tmp/v5b7jjU/390 2>&1" arg3=(fault) arg4=(fault) arg5=(fault) arg6=(fault) arg7=(fault) arg8=(fault) arg9=(fault) arg10=(fault) arg11=(fault) arg12="" arg13=(fault) arg14="isFoldable" arg15=(fault)


					 WorkerPool/4961-4961  [002] .... 11375.704112: sched_process_exit: comm=WorkerPool/4961 pid=4961 prio=120
					           slack-9761  [001] .... 11375.705486: sched_process_fork: comm=slack pid=9761 child_comm=slack child_pid=5123
					          chrome-10404 [000] .... 11377.791761: sched_process_fork: comm=chrome pid=10404 child_comm=chrome child_pid=5124
					 TaskSchedulerFo-5005  [003] .... 11380.022092: sched_process_exit: comm=TaskSchedulerFo pid=5005 prio=120
					           <...>-4400  [001] .... 11380.022282: sched_process_exit: comm=TaskSchedulerFo pid=4400 prio=120
					 TaskSchedulerFo-5015  [003] .... 11381.777781: sched_process_exit: comm=TaskSchedulerFo pid=5015 prio=120
		*/

		// check if we're interested in this event
		if this.selectEvent(eventLine) {
			this.bus <- eventLine
		}
	}
}

func (this *Probe) Enable() (err error) {
	this.Lock()
	defer this.Unlock()

	if this.enabled == true {
		return nil
	}

	if Available() == false {
		return ErrUnavailable
	}

	// enable all events
	for eventName, eventFileName := range this.events {
		if err = WriteFile(eventFileName, "1"); err != nil {
			return fmt.Errorf("Error while enabling event %s: %s", eventName, err)
		}
	}

	// create the custom kprobe consumer
	if err = WriteFile(SystemProbesFile, this.descriptor); err != nil {
		return fmt.Errorf("Error while enabling probe descriptor for %s: %s", this.name, err)
	}

	// enable the probe
	if err = WriteFile(this.fileName, "1"); err != nil {
		return fmt.Errorf("Error while enable probe %s: %s", this.name, err)
	}

	// create the handle to the pipe file
	if this.pipe, err = Reader(EventsPipeFile); err != nil {
		return fmt.Errorf("Error while opening %s: %s", EventsPipeFile, err)
	}

	this.enabled = true

	// start the async worker that will read events from the
	// pipe file and send them to the `bus` channel
	go this.worker()

	return nil
}

func (this *Probe) Disable() error {
	this.Lock()
	defer this.Unlock()

	if this.enabled == false {
		return nil
	}

	// disable all events
	for eventName, eventFileName := range this.events {
		if err := WriteFile(eventFileName, "0"); err != nil {
			return fmt.Errorf("Error while disabling event %s: %s", eventName, err)
		}
	}

	// disable the probe itself
	if err := WriteFile(this.fileName, "0"); err != nil {
		return fmt.Errorf("Error while disabling probe %s: %s", this.name, err)
	}

	// remove the probe from the system
	if err := AppendFile(SystemProbesFile, fmt.Sprintf("-:%s", this.name)); err != nil {
		return fmt.Errorf("Error while removing the probe %s: %s", this.name, err)
	}

	this.enabled = false
	this.pipe <- "<quit>"

	// wait for the worker to finish
	<-this.done

	return nil
}
