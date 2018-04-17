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
	bus chan Event
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
		bus:        make(chan Event),
	}
}

func (this *Probe) Enabled() bool {
	this.RLock()
	defer this.RUnlock()
	return this.enabled
}

func (this *Probe) Events() <-chan Event {
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
		// our parent go routine is telling us to quit
		if eventLine == "<quit>" {
			break
		}

		// check if we're interested in this event
		if this.selectEvent(eventLine) {
			// parse the raw event data
			if err, event := parseEvent(eventLine); err != nil {
				fmt.Printf("Error while parsing event: %s\n", err)
			} else {
				this.bus <- event
			}
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
