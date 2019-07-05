// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-istio-auth for terms.
package log

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var log *logrus.Logger

// InitLogger initializes a logger object with log rotation
func InitLogger(logFile, level string) {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.Warnln("Could not parse log level, defaulting to info. Error:", err.Error())
		logLevel = logrus.InfoLevel
	}

	logger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    1, // Mb
		MaxBackups: 5,
		MaxAge:     28, // Days
	}

	l := &logrus.Logger{
		Out: io.MultiWriter(os.Stdout, logger),
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

func Debugf(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

func Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

func Warningf(format string, args ...interface{}) {
	log.Warningf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	log.Panicf(format, args...)
}

func Debug(args ...interface{}) {
	log.Debug(args...)
}

func Info(args ...interface{}) {
	log.Info(args...)
}

func Print(args ...interface{}) {
	log.Print(args...)
}

func Warn(args ...interface{}) {
	log.Warn(args...)
}

func Warning(args ...interface{}) {
	log.Warning(args...)
}

func Error(args ...interface{}) {
	log.Error(args...)
}

func Fatal(args ...interface{}) {
	log.Fatal(args...)
}

func Panic(args ...interface{}) {
	log.Panic(args...)
}

func Debugln(args ...interface{}) {
	log.Debugln(args...)
}

func Infoln(args ...interface{}) {
	log.Infoln(args...)
}

func Println(args ...interface{}) {
	log.Println(args...)
}

func Warnln(args ...interface{}) {
	log.Warnln(args...)
}

func Warningln(args ...interface{}) {
	log.Warningln(args...)
}

func Errorln(args ...interface{}) {
	log.Errorln(args...)
}

func Fatalln(args ...interface{}) {
	log.Fatalln(args...)
}

func Panicln(args ...interface{}) {
	log.Panicln(args...)
}
