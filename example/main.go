package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/evilsocket/ftrace"
)

func setupSignals(cb func()) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		_ = <-sigChan
		cb()
		os.Exit(0)
	}()
}

func main() {
	subEvents := []string{
		"sched/sched_process_fork",
		"sched/sched_process_exec",
		"sched/sched_process_exit",
	}

	probe := ftrace.NewProbe("test_probe", "sys_execve", subEvents)

	if err := probe.Enable(); err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	setupSignals(func() {
		if err := probe.Disable(); err != nil {
			fmt.Printf("%s\n", err)
		} else {
			fmt.Printf("Probe disabled.\n")
		}
	})

	fmt.Printf("Probe is running ...\n")

	for e := range probe.Events() {
		if e.IsSyscall {
			fmt.Printf("SYSCALL %s\n", e)
		} else {
			fmt.Printf("\t%s\n", e)
		}
	}
}
