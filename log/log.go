package log

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type Logger struct {
	logger     *log.Logger
	mu         sync.Mutex
	formatFunc func(level string, str string) string
	output     io.Writer
	receivers  []Receiver
	Depth      int
	ctx        context.Context
}

type Receiver struct {
	writer     ReceiverWriter
	logger     *log.Logger
	level      LEVEL
	formatFunc formatFunc
	ctx        context.Context
}

type ReceiverWriter struct {
	ch chan []byte
}

func (r *ReceiverWriter) Write(p []byte) (int, error) {
	r.ch <- p
	return len(p), nil
}

func (r *ReceiverWriter) Chan() <-chan []byte {
	return r.ch
}

func (r *ReceiverWriter) Close() error {
	close(r.ch)
	return nil
}

type LEVEL string

const (
	Info    LEVEL = "Info"
	Warning LEVEL = "Warning"
	Debug   LEVEL = "Debug"
	Error   LEVEL = "Error"
	Fatal   LEVEL = "Fatal"
)

type formatFunc func(level string, str string) string

func New(ctx context.Context) *Logger {
	l := &Logger{
		mu:  sync.Mutex{},
		ctx: ctx,
	}
	if l.ctx == nil {
		l.ctx = context.Background()
	}
	l.formatFunc = l.DefaultFormatFunc
	l.Depth = 4
	l.output = os.Stdout
	l.logger = log.New(l.output, "", 0)
	return l
}

func (l *Logger) SetOutput(w io.Writer) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
	l.logger = log.New(w, "", 0)
	return l
}

func (l *Logger) SetDepth(depth int) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Depth = depth
	return l
}

func (l *Logger) SetReceiverToLogger(level LEVEL, formatFunc formatFunc) *log.Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.receivers == nil {
		l.receivers = make([]Receiver, 0)
	}
	r := Receiver{ctx: l.ctx, level: level}
	if formatFunc != nil {
		r.formatFunc = formatFunc
	} else {
		r.formatFunc = l.formatFunc
	}
	r.writer = ReceiverWriter{ch: make(chan []byte, 100)}
	logger := log.New(&r.writer, "", 0)
	r.logger = logger
	go func(r *Receiver, l *Logger) {
		defer r.writer.Close()
		for {
			select {
			case <-r.ctx.Done():
				return
			case data := <-r.writer.Chan():
				l.print(r.formatFunc, r.level, string(data))
			}
		}
	}(&r, l)
	return logger
}

func (l *Logger) SetReceiverToWriter(level LEVEL, formatFunc formatFunc) *ReceiverWriter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.receivers == nil {
		l.receivers = make([]Receiver, 0)
	}
	r := Receiver{ctx: l.ctx, level: level}
	if formatFunc != nil {
		r.formatFunc = formatFunc
	} else {
		r.formatFunc = l.formatFunc
	}
	r.writer = ReceiverWriter{ch: make(chan []byte, 100)}
	go func(r *Receiver, l *Logger) {
		defer r.writer.Close()
		for {
			select {
			case <-r.ctx.Done():
				return
			case data := <-r.writer.Chan():
				l.print(r.formatFunc, r.level, string(data))
			}
		}
	}(&r, l)
	l.receivers = append(l.receivers, r)
	return &r.writer
}

func (l *Logger) SetFormatFunc(f func(level string, str string) string) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.formatFunc = f
	return l
}

func (l *Logger) DefaultFormatFunc(level string, str string) string {
	file, line := FormatFuncHelper(l.Depth)
	return fmt.Sprintf("[%s] [%s:%s] [%s] %s", time.Now().Format("2006-01-02 15:04:05 UTC-07"), file, strconv.Itoa(line), level, str)
}

func FormatFuncHelper(depth int) (string, int) {
	_, file, line, ok := runtime.Caller(depth)
	if !ok {
		file = "???"
		line = 0
	}
	return file, line
}

func levelTranslate(level LEVEL) string {
	switch level {
	case Info:
		return "Info"
	case Warning:
		return "Warning"
	case Debug:
		return "Debug"
	case Error:
		return "Error"
	case Fatal:
		return "Fatal"
	default:
		return string(level)
	}
}

func CustomLevel(str string) LEVEL {
	return LEVEL(str)
}

func (l *Logger) print(formatFunc formatFunc, level LEVEL, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if formatFunc != nil {
		l.logger.Print(formatFunc(levelTranslate(level), fmt.Sprint(v...)))
	} else {
		l.logger.Print(v...)
	}
}

func (l *Logger) Print(level LEVEL, v ...any) {
	l.print(l.formatFunc, level, v...)
}

func (l *Logger) printf(formatFunc formatFunc, level LEVEL, format string, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if formatFunc != nil {
		l.logger.Print(formatFunc(levelTranslate(level), fmt.Sprintf(format, v...)))
	} else {
		l.logger.Printf(format, v...)
	}
}

func (l *Logger) Printf(level LEVEL, format string, v ...any) {
	l.printf(l.formatFunc, level, format, v...)
}

func (l *Logger) println(formatFunc formatFunc, level LEVEL, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	v = append(v, "\n")
	l.print(formatFunc, level, v...)
}

func (l *Logger) Println(level LEVEL, v ...any) {
	l.println(l.formatFunc, level, v...)
}

func (l *Logger) fatal(formatFunc formatFunc, level LEVEL, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if formatFunc != nil {
		l.logger.Fatal(formatFunc(levelTranslate(level), fmt.Sprint(v...)))
	} else {
		l.logger.Fatal(v...)
	}
}

func (l *Logger) Fatal(level LEVEL, v ...any) {
	l.fatal(l.formatFunc, level, v...)
}

func (l *Logger) fatalf(formatFunc formatFunc, level LEVEL, format string, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if formatFunc != nil {
		l.logger.Fatal(formatFunc(levelTranslate(level), fmt.Sprintf(format, v...)))
	} else {
		l.logger.Fatalf(format, v...)
	}
}

func (l *Logger) Fatalf(level LEVEL, format string, v ...any) {
	l.fatalf(l.formatFunc, level, format, v...)
}

func (l *Logger) fatalln(formatFunc formatFunc, level LEVEL, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	v = append(v, "\n")
	l.fatal(formatFunc, level, v...)
}

func (l *Logger) Fatalln(level LEVEL, v ...any) {
	l.fatalln(l.formatFunc, level, v...)
}

func (l *Logger) panic(formatFunc formatFunc, level LEVEL, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if formatFunc != nil {
		l.logger.Panic(formatFunc(levelTranslate(level), fmt.Sprint(v...)))
	} else {
		l.logger.Panic(v...)
	}
}

func (l *Logger) Panic(level LEVEL, v ...any) {
	l.panic(l.formatFunc, level, v...)
}

func (l *Logger) panicf(formatFunc formatFunc, level LEVEL, format string, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if formatFunc != nil {
		l.logger.Panic(formatFunc(levelTranslate(level), fmt.Sprintf(format, v...)))
	} else {
		l.logger.Panicf(format, v...)
	}
}

func (l *Logger) Panicf(level LEVEL, format string, v ...any) {
	l.panicf(l.formatFunc, level, format, v...)
}

func (l *Logger) panicln(formatFunc formatFunc, level LEVEL, v ...any) {
	if v == nil || len(v) == 0 {
		return
	}
	v = append(v, "\n")
	l.panic(formatFunc, level, v...)
}

func (l *Logger) Panicln(level LEVEL, v ...any) {
	l.panicln(l.formatFunc, level, v...)
}
