package cli

import "fmt"

// Process exit codes.
const (
	ExitOK       = 0 // success, no blocking findings
	ExitFindings = 1 // findings at or above fail_on, or score below min_score
	ExitUsage    = 2 // bad flags, arguments, configuration or rules
	ExitInternal = 3 // unexpected failure (I/O, ...)
)

// exitError carries a specific exit code. A nil err means "exit quietly".
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func usageError(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

func internalError(err error) error {
	return &exitError{code: ExitInternal, err: err}
}
