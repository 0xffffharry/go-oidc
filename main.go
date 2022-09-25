package main

import (
	"context"
	"flag"
	"fmt"
	"oidc/config"
	"oidc/log"
	"oidc/proxy"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	AppName    = "oidc"
	AppVersion = "v0.0.1"
)

func main() {
	ParamVersion := flag.Bool("v", false, "show version")
	ParamHelp := flag.Bool("h", false, "show help")
	ParamConfig := flag.String("c", "config.json", "config file")
	flag.Parse()
	if *ParamVersion {
		fmt.Println(fmt.Sprintf("%s(%s)", AppName, AppVersion))
		return
	}
	if *ParamHelp {
		flag.Usage()
		return
	}
	ctx, ctxCancel := context.WithCancel(context.Background())
	logger := log.New(ctx).SetOutput(os.Stdout).SetFormatFunc(func(level string, str string) string {
		return fmt.Sprintf("[%s] [%s] %s", time.Now().Format("2006-01-02 15:04:05 UTC-07"), level, str)
	}).SetDepth(2)
	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM|syscall.SIGKILL)
		<-c
		logger.Println(log.Warning, "Interrupt signal received, shutting down...")
		ctxCancel()
	}()
	logger.Println(log.Info, fmt.Sprintf("%s %s", AppName, AppVersion))
	logger.Println(log.Info, "Loading config...")
	cfg, err := config.ParseConfig(*ParamConfig)
	if err != nil {
		logger.Fatalln(log.Fatal, err)
		return
	}
	logger.Println(log.Info, "Starting servers...")
	globalConfig := proxy.Global{
		ProxyConfig: cfg.Servers,
		Ctx:         ctx,
		Logger:      logger,
	}
	globalConfig.Run()
	logger.Println(log.Info, "exit..")
}
