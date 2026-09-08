package swan

import "log/slog"

// Option tweaks runtime behavior without widening Config. Options are
// applied once in NewSession; the zero option set mirrors swan2 defaults.
type Option func(*options) error

// options aggregates everything Option can set. Unexported so users go
// through With* helpers only.
type options struct {
	// logger receives centralized human-friendly protocol logs prepared by
	// swan/debug. nil means logging is disabled.
	logger *slog.Logger
	// queueSizes overrides cfg.Queue when non-nil.
	queueSizes *QueueSizes
	// timeouts overrides cfg.Timeouts when non-nil.
	timeouts *Timeouts
}

// WithLogger installs the logger used for centralized debug output at packet
// and parse boundaries (swan/debug formatters). Passing nil disables logging.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) error {
		o.logger = logger
		return nil
	}
}

// WithQueueSizes overrides channel bounds from Config.
func WithQueueSizes(sizes QueueSizes) Option {
	return func(o *options) error {
		o.queueSizes = &sizes
		return nil
	}
}

// WithTimeouts overrides retransmission and reassembly timing from Config.
func WithTimeouts(timeouts Timeouts) Option {
	return func(o *options) error {
		o.timeouts = &timeouts
		return nil
	}
}
