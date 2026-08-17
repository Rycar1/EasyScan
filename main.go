package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/desktop"
	scanruntime "github.com/example/easyscan/internal/runtime"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	configPath := flag.String("config", "", "YAML configuration (defaults to a nearby easyscan.yaml)")
	flag.Parse()
	path, err := desktopConfigPath(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	scan, err := scanruntime.Open(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	app, lifecycle := desktop.New(scan)
	err = wails.Run(&options.App{
		Title:            "EasyScan",
		Width:            1360,
		Height:           900,
		MinWidth:         1024,
		MinHeight:        700,
		BackgroundColour: &options.RGBA{R: 20, G: 22, B: 24, A: 1},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        lifecycle.Startup,
		OnShutdown:       lifecycle.Shutdown,
		DisableResize:    false,
		Frameless:        false,
		Bind:             []interface{}{app},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		_ = scan.Close(context.Background())
		os.Exit(1)
	}
}

// desktopConfigPath lets a user launch build\\bin\\easyscan-desktop.exe by
// double-clicking it during local use. Windows then uses build\\bin as the
// working directory, while the project configuration normally lives two
// levels above it. An explicitly supplied -config value always wins.
func desktopConfigPath(requested string) (string, error) {
	if requested != "" {
		return requested, nil
	}

	candidates := make([]string, 0, 4)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "easyscan.yaml"))
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		candidates = append(candidates, filepath.Join(directory, "easyscan.yaml"))
		candidates = append(candidates, filepath.Join(filepath.Dir(directory), "easyscan.yaml"))
		candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Dir(directory)), "easyscan.yaml"))
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("cannot find easyscan.yaml; place it next to the desktop executable or start with -config <path>")
}
