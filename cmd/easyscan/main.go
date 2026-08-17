package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/easyscan/internal/config"
	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/importer"
	"github.com/example/easyscan/internal/model"
	"github.com/example/easyscan/internal/proxy"
	"github.com/example/easyscan/internal/report"
	scanruntime "github.com/example/easyscan/internal/runtime"
)

type outputs struct{ json, html, sarif string }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "analyze":
		err = analyze(os.Args[2:])
	case "rules":
		err = validateRules(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "easyscan.yaml", "YAML configuration")
	proxyListen := fs.String("listen", "", "override proxy listen address")
	apiListen := fs.String("api-listen", "", "override API listen address")
	out := bindOutputs(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *proxyListen != "" {
		cfg.Proxy.Listen = *proxyListen
	}
	if *apiListen != "" {
		cfg.API.Listen = *apiListen
	}
	scan, err := scanruntime.Open(cfg)
	if err != nil {
		return err
	}
	defer scan.Close(context.Background())
	e := scan.Engine()
	defer func() {
		if reportErr := writeReports(e, *out); reportErr != nil {
			fmt.Fprintln(os.Stderr, "report error:", reportErr)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	api := &http.Server{Addr: cfg.API.Listen, Handler: scan.HTTPHandler()}
	apiListener, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("listen api %s: %w", cfg.API.Listen, err)
	}
	defer apiListener.Close()
	errCh := make(chan error, 1)
	go func() { <-ctx.Done(); _ = api.Shutdown(context.Background()) }()
	go func() { errCh <- api.Serve(apiListener) }()
	fmt.Printf("EasyScan passive proxy: http://%s\n", cfg.Proxy.Listen)
	fmt.Printf("EasyScan traffic API:  http://%s/api/v1/traffic\n", cfg.API.Listen)
	fmt.Println("EasyScan desktop:      run easyscan-desktop.exe (Wails/WebView2)")
	fmt.Println("主动扫描：可用（仅对 scope.allow_hosts 内且已授权的目标发起，请确保已取得授权）")
	proxyServer := proxy.New(e, cfg.Proxy.MaxBodyBytes)
	if cfg.Proxy.MITM {
		caPath, err := proxyServer.EnableMITM(cfg.Proxy.CADir)
		if err != nil {
			return fmt.Errorf("enable HTTPS interception: %w", err)
		}
		fmt.Printf("HTTPS interception: enabled for scope.allow_hosts; trust CA: %s\n", caPath)
	}
	proxyErr := proxyServer.ListenAndServe(ctx, cfg.Proxy.Listen)
	if proxyErr != nil {
		stop()
		return proxyErr
	}
	apiErr := <-errCh
	if apiErr != nil && !errors.Is(apiErr, http.ErrServerClosed) {
		return apiErr
	}
	return nil
}

func analyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	configPath := fs.String("config", "easyscan.yaml", "YAML configuration")
	harPath := fs.String("har", "", "HAR file to analyze")
	burpPath := fs.String("burp-xml", "", "Burp Suite XML export to analyze")
	out := bindOutputs(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*harPath == "" && *burpPath == "") || (*harPath != "" && *burpPath != "") {
		return errors.New("provide exactly one of --har or --burp-xml")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	scan, err := scanruntime.Open(cfg)
	if err != nil {
		return err
	}
	defer scan.Close(context.Background())
	e := scan.Engine()
	var transactions []model.Transaction
	if *harPath != "" {
		transactions, err = importer.HAR(*harPath)
	} else {
		transactions, err = importer.BurpXML(*burpPath)
	}
	if err != nil {
		return err
	}
	for _, tx := range transactions {
		e.Analyze(tx)
	}
	if err := writeReports(e, *out); err != nil {
		return err
	}
	fmt.Printf("Analyzed %d transaction(s): %d unique finding(s), %d asset(s)\n", len(transactions), len(e.Findings()), len(e.Assets()))
	return nil
}

func validateRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	configPath := fs.String("config", "easyscan.yaml", "YAML configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	e, err := engine.New(cfg)
	if err != nil {
		return err
	}
	hfinger := e.HFingerStats()
	fmt.Printf("Validated %d passive rule file(s); loaded %d passive rules and %d HFinger rules (%d custom rules from %d files, %d failed files).\n", len(cfg.Rules.Files), e.RuleCount(), hfinger.Loaded, hfinger.CustomRules, hfinger.CustomFiles, hfinger.FailedFiles)
	return nil
}

func bindOutputs(fs *flag.FlagSet) *outputs {
	out := new(outputs)
	fs.StringVar(&out.json, "json-output", "", "write findings JSON")
	fs.StringVar(&out.html, "html-output", "", "write HTML report")
	fs.StringVar(&out.sarif, "sarif-output", "", "write SARIF 2.1.0 report")
	return out
}
func writeReports(e *engine.Engine, out outputs) error {
	if err := report.WriteJSON(out.json, e.Findings()); err != nil {
		return err
	}
	if err := report.WriteHTML(out.html, e.Findings(), e.Assets()); err != nil {
		return err
	}
	return report.WriteSARIF(out.sarif, e.Findings())
}

func usage() {
	fmt.Fprint(os.Stderr, `EasyScan — local-first passive HTTP security analysis

Usage:
  easyscan serve [--config easyscan.yaml] [--listen 127.0.0.1:7777] [--api-listen 127.0.0.1:8787] [output flags]
  easyscan analyze (--har capture.har | --burp-xml burp-items.xml) [--config easyscan.yaml] [output flags]
  easyscan rules [--config easyscan.yaml]

Output flags: --json-output FILE --html-output FILE --sarif-output FILE
`)
}
