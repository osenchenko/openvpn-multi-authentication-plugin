package globals

import "errors"

var ErrAuthenticationFailed = errors.New("Authentication failed")

//AppLogger describes the zap interface
type AppLogger interface {
	DPanic(args ...interface{})
	DPanicf(template string, args ...interface{})
	DPanicw(msg string, keysAndValues ...interface{})
	Debug(args ...interface{})
	Debugf(template string, args ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Error(args ...interface{})
	Errorf(template string, args ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Fatal(args ...interface{})
	Fatalf(template string, args ...interface{})
	Fatalw(msg string, keysAndValues ...interface{})
	Info(args ...interface{})
	Infof(template string, args ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Panic(args ...interface{})
	Panicf(template string, args ...interface{})
	Panicw(msg string, keysAndValues ...interface{})
	Warn(args ...interface{})
	Warnf(template string, args ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
}

//DummyLogger is used in tests
type DummyLogger struct{}

func (dl *DummyLogger) DPanic(args ...interface{})                       {}
func (dl *DummyLogger) DPanicf(template string, args ...interface{})     {}
func (dl *DummyLogger) DPanicw(msg string, keysAndValues ...interface{}) {}
func (dl *DummyLogger) Debug(args ...interface{})                        {}
func (dl *DummyLogger) Debugf(template string, args ...interface{})      {}
func (dl *DummyLogger) Debugw(msg string, keysAndValues ...interface{})  {}
func (dl *DummyLogger) Error(args ...interface{})                        {}
func (dl *DummyLogger) Errorf(template string, args ...interface{})      {}
func (dl *DummyLogger) Errorw(msg string, keysAndValues ...interface{})  {}
func (dl *DummyLogger) Fatal(args ...interface{})                        {}
func (dl *DummyLogger) Fatalf(template string, args ...interface{})      {}
func (dl *DummyLogger) Fatalw(msg string, keysAndValues ...interface{})  {}
func (dl *DummyLogger) Info(args ...interface{})                         {}
func (dl *DummyLogger) Infof(template string, args ...interface{})       {}
func (dl *DummyLogger) Infow(msg string, keysAndValues ...interface{})   {}
func (dl *DummyLogger) Panic(args ...interface{})                        {}
func (dl *DummyLogger) Panicf(template string, args ...interface{})      {}
func (dl *DummyLogger) Panicw(msg string, keysAndValues ...interface{})  {}
func (dl *DummyLogger) Warn(args ...interface{})                         {}
func (dl *DummyLogger) Warnf(template string, args ...interface{})       {}
func (dl *DummyLogger) Warnw(msg string, keysAndValues ...interface{})   {}
