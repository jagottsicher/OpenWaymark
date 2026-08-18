// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Command owmmonitor runs an independent OpenWaymark log monitor.
//
//	owmmonitor init [-config owm-monitor.json]   create a default configuration
//	owmmonitor run  [-config owm-monitor.json]   start watching
//	owmmonitor version                           print version
//
// There is no admin surface and nothing to serve: a monitor holds no
// identity of its own and answers no requests, it only watches. See the
// package README and spec/owm-5-federation.md §4.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"openwaymark.org/owm/monitor"
)

const defaultConfigPath = "owm-monitor.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "owmmonitor: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("no subcommand given")
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "version":
		fmt.Println(version())
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `owmmonitor - independent OpenWaymark log monitor

  owmmonitor init [-config owm-monitor.json]  create a default configuration
  owmmonitor run  [-config owm-monitor.json]  start watching
  owmmonitor version                          print version

`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path of the configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(*path); err == nil {
		fmt.Printf("configuration %s left unchanged\n", *path)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	cfg := monitor.DefaultConfig()
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the configuration: %w", err)
	}
	buf = append(buf, '\n')
	if dir := filepath.Dir(*path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating the directory: %w", err)
		}
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("writing the configuration: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("writing the configuration: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("configuration created: %s\n", *path)
	fmt.Println("add targets under \"targets\" before running \"owmmonitor run\" — an empty list watches nothing.")
	return nil
}

func loadConfig(path string) (monitor.Config, error) {
	cfg, err := monitor.LoadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg = monitor.DefaultConfig()
		return cfg, cfg.Check()
	}
	return cfg, err
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path of the configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if len(cfg.Targets) == 0 {
		fmt.Println("no targets configured — watching nothing until the config is edited and owmmonitor is restarted")
	}
	for _, t := range cfg.Targets {
		if t.BaseURL != "" {
			fmt.Printf("watching  %-20s %s\n", t.Name, t.BaseURL)
		} else {
			fmt.Printf("watching  %-20s %s (resolved via DNS)\n", t.Name, t.Domain)
		}
	}
	fmt.Printf("findings  %s\n", cfg.FindingsDir)

	m, err := monitor.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := m.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	fmt.Println("stopped")
	return nil
}

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "owmmonitor (unknown version)"
	}
	rev, dirty := "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	if rev == "" {
		return fmt.Sprintf("owmmonitor %s (%s)", info.Main.Version, info.GoVersion)
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return fmt.Sprintf("owmmonitor %s%s (%s)", rev, dirty, info.GoVersion)
}
