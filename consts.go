package ftrace

const (
	MaxArguments      = 16
	EnabledStatusFile = "/proc/sys/kernel/ftrace_enabled"
	SystemProbesFile  = "/sys/kernel/debug/tracing/kprobe_events"
	EventsPipeFile    = "/sys/kernel/debug/tracing/trace_pipe"
	ProbeFileFmt      = "/sys/kernel/debug/tracing/events/kprobes/%s/enable"
	EventProbeFileFmt = "/sys/kernel/debug/tracing/events/%s/enable"
)
