// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package log

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	defaultDepth = 2
	pkgPrefix    = "github.com/yahoo/k8s-athenz-istio-auth/pkg/"
)

var log *logrus.Logger

// InitLogger initializes a logger object with log rotation
func InitLogger(logFile, level string) {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.Warnln("Could not parse log level, defaulting to info. Error:", err.Error())
		logLevel = logrus.InfoLevel
	}

	ioWriter := io.Writer(os.Stdout)
	if logFile != "" {
		logger := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    1, // Mb
			MaxBackups: 5,
			MaxAge:     28, // Days
		}
		ioWriter = io.MultiWriter(os.Stdout, logger)
	}

	l := &logrus.Logger{
		Out: ioWriter,
		Formatter: &logrus.TextFormatter{
			ForceColors:            true,
			DisableSorting:         true,
			FullTimestamp:          true,
			DisableLevelTruncation: true,
		},
		Level: logLevel,
	}
	l.SetNoLock()

	dir := filepath.Dir(logFile)
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		logrus.Errorln("Could not mkdir for log file, defaulting to stdout logging. Error:", err.Error())
		l.Out = os.Stdout
	}

	log = l
}

// getCallerInfo retrieves the function caller information and creates a
// log prefix out of callers package name, filename, and function name.
func getCallerInfo(depth int) string {
	pc, file, _, ok := runtime.Caller(depth)
	if !ok {
		return "[???/???] [???]"
	}

	_, filename := path.Split(file)
	fullCallPath := strings.Split(runtime.FuncForPC(pc).Name(), ".")
	fnName := fullCallPath[len(fullCallPath)-1]

	if len(fullCallPath) < 2 {
		return "[???/" + filename + "] [" + fnName + "]"
	}

	pkgName := ""
	fullPkgName := fullCallPath[len(fullCallPath)-2]
	if len(fullCallPath) >= 1 && fullPkgName[0] == '(' {
		pkgName = strings.Join(fullCallPath[0:len(fullCallPath)-2], ".")
	} else {
		pkgName = strings.Join(fullCallPath[0:len(fullCallPath)-1], ".")
	}

	pkgName = strings.TrimPrefix(pkgName, pkgPrefix)
	return "[" + pkgName + "/" + filename + "] [" + fnName + "]"
}

func Debugf(format string, args ...interface{}) {
	log.Debugf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Printf(format string, args ...interface{}) {
	log.Printf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Warnf(format string, args ...interface{}) {
	log.Warnf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Warningf(format string, args ...interface{}) {
	log.Warningf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Fatalf(format string, args ...interface{}) {
	log.Fatalf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Panicf(format string, args ...interface{}) {
	log.Panicf(getCallerInfo(defaultDepth)+" "+format, args...)
}

func Debug(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Debug(args...)
}

func Info(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Info(args...)
}

func Print(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Print(args...)
}

func Warn(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Warn(args...)
}

func Warning(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Warning(args...)
}

func Error(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Error(args...)
}

func Fatal(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Fatal(args...)
}

func Panic(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth), " "}, args...)
	log.Panic(args...)
}

func Debugln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Debugln(args...)
}

func Infoln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Infoln(args...)
}

func Println(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Println(args...)
}

func Warnln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Warnln(args...)
}

func Warningln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Warningln(args...)
}

func Errorln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Errorln(args...)
}

func Fatalln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Fatalln(args...)
}

func Panicln(args ...interface{}) {
	args = append([]interface{}{getCallerInfo(defaultDepth)}, args...)
	log.Panicln(args...)
}
