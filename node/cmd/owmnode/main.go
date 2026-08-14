// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Command owmnode runs an OpenWaymark node.
//
//	owmnode init  [-config owm.json]   create configuration and identity
//	owmnode serve [-config owm.json]   start the node
//	owmnode show  [-config owm.json]   print identity and log ID
//	owmnode version                    print version
//
// Day-to-day operation — admitting keys, erasing payloads, issuing STHs — goes
// through the admin interface of the running node and not through further
// subcommands. Two processes on the same SQLite file would be a way to wreck
// the database, and the detour through HTTP costs nothing.
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

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/node"
)

const defaultConfigPath = "owm.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "owmnode: %v\n", err)
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
	case "serve":
		return cmdServe(args[1:])
	case "show":
		return cmdShow(args[1:])
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
	fmt.Fprint(os.Stderr, `owmnode - OpenWaymark node

  owmnode init  [-config owm.json]  create configuration and identity
  owmnode serve [-config owm.json]  start the node
  owmnode show  [-config owm.json]  print identity and log ID
  owmnode version                   print version

`)
}

// loadConfig reads the configuration; if the file is missing, the defaults
// apply.
func loadConfig(path string) (node.Config, error) {
	cfg, err := node.LoadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg = node.DefaultConfig()
		return cfg, cfg.Check()
	}
	return cfg, err
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path of the configuration file")
	name := fs.String("operator", "", "name of the responsible operator")
	contact := fs.String("contact", "", "contact for access and erasure requests")
	baseURL := fs.String("base-url", "", "externally reachable address of this node")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := node.DefaultConfig()
	if _, err := os.Stat(*path); err == nil {
		// An existing configuration is read, not overwritten.
		cfg, err = node.LoadConfig(*path)
		if err != nil {
			return err
		}
		fmt.Printf("configuration %s left unchanged\n", *path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		// New configuration: paths relative to the configuration file so that
		// the directory can be moved as a whole.
		dir := filepath.Dir(*path)
		cfg.Database = filepath.Join(dir, node.DefaultDatabase)
		cfg.Identity = filepath.Join(dir, node.DefaultIdentity)
		cfg.Operator = node.Operator{Name: *name, Contact: *contact}
		cfg.BaseURL = *baseURL
		if err := writeConfig(*path, cfg); err != nil {
			return err
		}
		fmt.Printf("configuration created: %s\n", *path)
	}

	// The identity is created only if it is missing. Overwriting an existing one
	// would mean continuing the log under a new identifier — every STH so far
	// would then be from a key nobody knows any more.
	id, err := node.LoadOrCreateIdentity(cfg.Identity, core.SigAlgMLDSA65)
	if err != nil {
		return err
	}
	return printIdentity(cfg, id)
}

func writeConfig(path string, cfg node.Config) error {
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the configuration: %w", err)
	}
	buf = append(buf, '\n')
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating the directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("writing the configuration: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("writing the configuration: %w", err)
	}
	return f.Close()
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path of the configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	id, err := node.LoadIdentity(cfg.Identity)
	if err != nil {
		return err
	}
	return printIdentity(cfg, id)
}

func printIdentity(cfg node.Config, id *node.Identity) error {
	logID, err := id.LogID()
	if err != nil {
		return err
	}
	pub := id.Key.Public()
	fmt.Printf("log ID:      %s\n", logID)
	fmt.Printf("key:         %s (%s)\n", pub.ID(), pub.Alg())
	fmt.Printf("genesis key: %s\n", id.Genesis.ID())
	fmt.Printf("identity:    %s\n", cfg.Identity)
	fmt.Printf("database:    %s\n", cfg.Database)
	fmt.Printf("public:      %s\n", cfg.Listen)
	fmt.Printf("admin:       %s\n", cfg.AdminListen)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path of the configuration file")
	listen := fs.String("listen", "", "address of the public API (overrides the configuration)")
	admin := fs.String("admin", "", "address of the admin interface (overrides the configuration)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *admin != "" {
		cfg.AdminListen = *admin
	}

	// SIGINT and SIGTERM shut down in order: the last tree state is still signed
	// before the process leaves.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	n, err := node.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer n.Close()

	logID, err := n.Identity().LogID()
	if err != nil {
		return err
	}
	size, err := n.Log().Size(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("log %s, %d entries\n", logID, size)
	fmt.Printf("public   http://%s/\n", cfg.Listen)
	if cfg.AdminListen != "" {
		fmt.Printf("admin    http://%s/  (no authentication - keep it local)\n", cfg.AdminListen)
	}
	for _, p := range n.Profiles().IDs() {
		fmt.Printf("profile  %s\n", p)
	}

	if err := n.Run(ctx); err != nil {
		return err
	}
	fmt.Println("stopped")
	return nil
}

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "owmnode (unknown version)"
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
		return fmt.Sprintf("owmnode %s (%s)", info.Main.Version, info.GoVersion)
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return fmt.Sprintf("owmnode %s%s (%s)", rev, dirty, info.GoVersion)
}
