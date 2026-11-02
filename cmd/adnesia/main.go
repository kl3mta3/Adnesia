// Command adnesia is a self-owned, system-wide ad blocker for Windows.
//
// It generates a local root CA, installs it into the user's trust store, runs
// a filtering MITM proxy, points the Windows system proxy at it, and shows a
// tray icon plus a local web dashboard. The proxy blocks ad/tracker requests,
// injects cosmetic-hiding CSS, strips YouTube ads, and tunnels pinned hosts
// through untouched. On shutdown it restores the previous system-proxy setting.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"adnesia/internal/autostart"
	"adnesia/internal/bypass"
	"adnesia/internal/ca"
	"adnesia/internal/config"
	"adnesia/internal/cosmetic"
	"adnesia/internal/filter"
	"adnesia/internal/lists"
	"adnesia/internal/proxy"
	"adnesia/internal/redirect"
	"adnesia/internal/stats"
	"adnesia/internal/sysproxy"
	"adnesia/internal/transparent"
	"adnesia/internal/tray"
	"adnesia/internal/web"
)

// build is stamped at link time (-X main.build=...) and shown on the dashboard
// so it's always clear which copy is running.
var build = "dev"

type flags struct {
	verbose      bool
	noSysProxy   bool
	noInstall    bool
	noTray       bool
	transparent  bool
	cosGeneric   bool
	uninstall    bool
	resetProxy   bool
	bypassList   bool
	bypassAdd    string
	bypassRemove string
	autostartOn  bool
	autostartOff bool
	autostatus   bool
	watchdogPID  int
}

func main() {
	var f flags
	flag.BoolVar(&f.verbose, "v", false, "verbose (debug) logging")
	flag.BoolVar(&f.noSysProxy, "no-sysproxy", false, "do not touch the Windows system proxy (useful for testing)")
	flag.BoolVar(&f.noInstall, "no-install", false, "do not install the CA into the trust store")
	flag.BoolVar(&f.noTray, "no-tray", false, "run headless (no tray icon); stop with Ctrl+C")
	flag.BoolVar(&f.transparent, "transparent", false, "Kernel Mode (EXPERIMENTAL): intercept at the driver level so apps that ignore the system proxy are filtered too (needs WinDivert + admin)")
	flag.BoolVar(&f.cosGeneric, "cosmetic-generic", false, "inject generic (site-agnostic) cosmetic selectors on every page")
	flag.BoolVar(&f.uninstall, "uninstall", false, "remove the CA from the trust store and reset the system proxy, then exit")
	flag.BoolVar(&f.resetProxy, "reset-proxy", false, "clear Adnesia's system-proxy settings (restore direct internet), then exit")
	flag.BoolVar(&f.bypassList, "bypass-list", false, "print the passthrough host list and exit")
	flag.StringVar(&f.bypassAdd, "bypass-add", "", "add a host pattern to the passthrough list and exit")
	flag.StringVar(&f.bypassRemove, "bypass-remove", "", "remove a runtime-added passthrough pattern and exit")
	flag.BoolVar(&f.autostartOn, "install-autostart", false, "register Adnesia to start at login, then exit")
	flag.BoolVar(&f.autostartOff, "uninstall-autostart", false, "remove the login auto-start entry, then exit")
	flag.BoolVar(&f.autostatus, "autostart-status", false, "report whether login auto-start is enabled, then exit")
	flag.IntVar(&f.watchdogPID, "watchdog", 0, "internal: watch this PID and reset the system proxy when it exits")
	flag.Parse()

	level := slog.LevelInfo
	if f.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(logWriter(), &slog.HandlerOptions{Level: level}))

	// Watchdog mode: a detached helper that clears the system proxy if the
	// main process dies unexpectedly, so a crash never leaves you offline.
	if f.watchdogPID > 0 {
		runWatchdog(f.watchdogPID)
		return
	}

	if err := run(log, f); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// logWriter sends logs to stderr and, when possible, to a rotating-ish file in
// the data dir. The file matters for the no-console (tray) build, where stderr
// goes nowhere.
func logWriter() io.Writer {
	dir, err := config.Dir()
	if err != nil {
		return os.Stderr
	}
	path := filepath.Join(dir, "adnesia.log")
	// Keep the file from growing without bound: truncate if it's over ~5 MB.
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return os.Stderr
	}
	return io.MultiWriter(os.Stderr, f)
}

func run(log *slog.Logger, f flags) error {
	// Fast path: just clear the proxy settings and exit (connectivity rescue).
	if f.resetProxy {
		if err := sysproxy.Reset(); err != nil {
			return err
		}
		fmt.Println("system proxy cleared — direct internet restored")
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	bp, err := bypass.NewManager(cfg.DataDir(), cfg.BypassDomains, log)
	if err != nil {
		return err
	}

	// Management commands run and exit without starting anything.
	if handled, err := handleBypassCommands(f, bp); handled || err != nil {
		return err
	}
	if handled, err := handleAutostart(f); handled || err != nil {
		return err
	}

	authority, err := ca.EnsureCA(cfg.DataDir())
	if err != nil {
		return err
	}
	if f.uninstall {
		return doUninstall(log, authority, f.noSysProxy)
	}

	log.Info("config loaded", "dir", cfg.DataDir(), "proxy", cfg.ProxyAddr, "dashboard", cfg.DashboardAddr)
	a := &app{log: log, f: f, cfg: cfg, bypass: bp, authority: authority}

	// Restore the proxy if the console is closed or the machine logs off.
	installConsoleCtrlHandler(a.stop)

	if f.noTray {
		if err := a.start(); err != nil {
			return err
		}
		waitForSignal(log)
		a.stop()
		return nil
	}

	// Tray owns the main thread; the core starts in onReady and stops in onExit.
	tray.Run(tray.Handlers{
		OnStart:       a.start,
		OnStop:        a.stop,
		Enabled:       a.Enabled,
		SetEnabled:    a.SetEnabled,
		OpenDashboard: a.OpenDashboard,
		Log:           log,
	})
	return nil
}

// app holds the running core components.
type app struct {
	log       *slog.Logger
	f         flags
	cfg       *config.Config
	bypass    *bypass.Manager
	authority *ca.CA

	proxy    *proxy.Proxy
	web      *web.Server
	sp        *sysproxy.Controller
	watchdog  *os.Process
	caTrusted bool
	stats    *stats.Stats
	engine *filter.Engine
	cos    *cosmetic.Engine

	mu            sync.Mutex // guards transparent start/stop
	redir         *redirect.Engine
	trans         *transparent.Server
	transparentErr string
}

// start brings up the CA trust, filter engines, proxy, dashboard and system
// proxy. It is safe to call once.
func (a *app) start() error {
	if a.f.noInstall {
		a.log.Info("CA trust install skipped (-no-install)", "thumbprint", a.authority.Thumbprint())
	} else if err := a.authority.InstallTrust(); err != nil {
		// Not fatal: we keep running, but we will not route traffic through a
		// certificate Windows doesn't trust (that would break every HTTPS site).
		a.log.Warn("could not install CA into trust store", "err", err)
	}
	a.caTrusted = a.authority.IsTrusted()
	if a.caTrusted {
		a.log.Info("CA trusted", "cert", a.authority.CertPath(), "thumbprint", a.authority.Thumbprint())
	} else {
		a.log.Warn("CA NOT trusted by Windows; system proxy will stay off", "thumbprint", a.authority.Thumbprint())
	}

	lm, err := lists.New(a.cfg.DataDir(), a.cfg.Lists, 24*time.Hour, a.log)
	if err != nil {
		return err
	}
	a.engine, a.cos, err = lm.Build(context.Background())
	if err != nil {
		return err
	}

	a.stats = stats.New(500)
	a.proxy, err = proxy.New(proxy.Options{
		Addr:          a.cfg.ProxyAddr,
		CACert:        a.authority.TLS,
		Bypass:        a.bypass,
		Engine:        a.engine,
		Cosmetic:      a.cos,
		Stats:         a.stats,
		InjectGeneric: a.cfg.CosmeticGeneric || a.f.cosGeneric,
		Log:           a.log,
	})
	if err != nil {
		return err
	}
	a.proxy.SetEnabled(a.cfg.Enabled) // honor the saved on/off state
	a.applySettings()                 // apply saved per-feature toggles
	go func() {
		if err := a.proxy.Start(); err != nil && err.Error() != "http: Server closed" {
			a.log.Error("proxy stopped", "err", err)
		}
	}()

	a.web = web.New(web.Options{
		Addr:          a.cfg.DashboardAddr,
		Controller:    a,
		Stats:         a.stats,
		Bypass:        a.bypass,
		NetworkRules:  a.engine.Count(),
		CosmeticRules: a.cos.Count(),
		ProxyAddr:     a.cfg.ProxyAddr,
		Build:         build,
		Log:           a.log,
	})
	go func() {
		if err := a.web.Start(); err != nil && err.Error() != "http: Server closed" {
			a.log.Error("dashboard stopped", "err", err)
		}
	}()

	if !a.f.noSysProxy {
		a.sp = &sysproxy.Controller{}
		if a.proxy.Enabled() {
			a.applySystemProxy()
		}
	} else {
		a.log.Info("system proxy left untouched (-no-sysproxy)")
	}

	if a.f.transparent || a.cfg.Transparent {
		if err := a.startTransparent(); err != nil {
			a.transparentErr = friendlyTransErr(err)
			a.log.Warn("transparent capture disabled", "err", err)
		}
	}

	a.log.Info("adnesia running", "dashboard", "http://"+a.cfg.DashboardAddr)
	return nil
}

// startTransparent brings up the EXPERIMENTAL WinDivert capture path. It is
// idempotent and returns an error (e.g. not elevated, or WinDivert missing)
// instead of only logging, so the dashboard toggle can report why it failed.
func (a *app) startTransparent() error {
	if a.trans != nil {
		return nil // already running
	}
	signer, err := ca.NewSigner(a.authority)
	if err != nil {
		return err
	}
	port := a.cfg.TransparentPort
	redir := redirect.New(uint16(port), a.log)
	if err := redir.Start(); err != nil {
		return err
	}
	trans := transparent.New(transparent.Options{
		Addr:          fmt.Sprintf("0.0.0.0:%d", port),
		Lookup:        redir.Lookup,
		Signer:        signer,
		Bypass:        a.bypass,
		Engine:        a.engine,
		Cosmetic:      a.cos,
		InjectGeneric: a.proxy.InjectGeneric(),
		Stats:         a.stats,
		Enabled:       a.proxy.Enabled,
		Log:           a.log,
	})
	go func() {
		if err := trans.Start(); err != nil {
			a.log.Warn("transparent listener stopped", "err", err)
		}
	}()
	a.redir, a.trans = redir, trans
	return nil
}

// stopTransparent tears down the WinDivert capture path.
func (a *app) stopTransparent() {
	if a.trans != nil {
		a.trans.Stop()
		a.trans = nil
	}
	if a.redir != nil {
		a.redir.Stop()
		a.redir = nil
	}
}

// setTransparent is the dashboard toggle for the experimental capture path.
func (a *app) setTransparent(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if on {
		if err := a.startTransparent(); err != nil {
			a.transparentErr = friendlyTransErr(err)
			a.cfg.Transparent = false
			a.log.Warn("transparent enable failed", "err", err)
			return
		}
		a.transparentErr = ""
		a.cfg.Transparent = true
	} else {
		a.stopTransparent()
		a.transparentErr = ""
		a.cfg.Transparent = false
	}
}

// TransparentStatus is a short human-readable state for the dashboard.
func (a *app) TransparentStatus() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.trans != nil {
		return "active (experimental)"
	}
	if a.transparentErr != "" {
		return a.transparentErr
	}
	return "off"
}

func friendlyTransErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "Access is denied"):
		return "needs administrator"
	case strings.Contains(s, "not installed"), strings.Contains(s, "could not be found"):
		return "WinDivert not installed"
	default:
		return s
	}
}

// stop tears the core down and restores the system proxy.
func (a *app) stop() {
	if a.trans != nil {
		a.trans.Stop()
	}
	if a.redir != nil {
		a.redir.Stop()
	}
	if a.sp != nil {
		if err := a.sp.Unset(); err != nil {
			a.log.Warn("restoring system proxy", "err", err)
		} else {
			a.log.Info("system proxy restored")
		}
	}
	a.stopWatchdog() // we restored the proxy ourselves; don't let it act
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a.web != nil {
		_ = a.web.Stop(ctx)
	}
	if a.proxy != nil {
		_ = a.proxy.Stop(ctx)
	}
	if a.stats != nil {
		snap := a.stats.Snapshot()
		a.log.Info("session stats", "requests", snap.Total, "blocked", snap.Blocked)
	}
}

// Enabled reports whether filtering is currently on.
func (a *app) Enabled() bool {
	return a.proxy != nil && a.proxy.Enabled()
}

// SetEnabled turns Adnesia on or off. Turning OFF also removes the system
// proxy so traffic goes direct (normal internet); turning ON re-applies the
// PAC. The choice is persisted so it survives a restart.
func (a *app) SetEnabled(on bool) {
	if a.proxy == nil {
		return
	}
	a.proxy.SetEnabled(on)
	if a.sp != nil {
		if on {
			a.caTrusted = a.authority.IsTrusted() // re-check: may have been approved since start
			a.applySystemProxy()
		} else {
			if err := a.sp.Unset(); err != nil {
				a.log.Warn("clear system proxy", "err", err)
			}
			a.stopWatchdog()
		}
	}
	a.cfg.Enabled = on
	if err := a.cfg.Save(); err != nil {
		a.log.Warn("save config", "err", err)
	}
	a.log.Info("filtering toggled", "enabled", on)
}

// applySettings pushes the saved feature toggles into the running proxy/engine.
func (a *app) applySettings() {
	if a.proxy == nil {
		return
	}
	a.proxy.SetCategory(filter.CatAds, a.cfg.AdBlocking)
	a.proxy.SetCategory(filter.CatPrivacy, a.cfg.Privacy)
	a.proxy.SetCategory(filter.CatSecurity, a.cfg.WebProtection)
	a.proxy.SetCategory(filter.CatAnnoyances, a.cfg.Annoyances)
	a.proxy.SetGhost(a.cfg.GhostMode)
	a.proxy.SetInjectGeneric(a.cfg.CosmeticGeneric || a.f.cosGeneric)
}

// Features reports the live on/off state of each dashboard toggle.
func (a *app) Features() map[string]bool {
	if a.proxy == nil {
		return map[string]bool{}
	}
	return map[string]bool{
		"ad_blocking":         a.proxy.CategoryEnabled(filter.CatAds),
		"privacy_protection":  a.proxy.CategoryEnabled(filter.CatPrivacy),
		"web_protection":      a.proxy.CategoryEnabled(filter.CatSecurity),
		"annoyances_blocking": a.proxy.CategoryEnabled(filter.CatAnnoyances),
		"ghost_mode":          a.proxy.Ghost(),
		"cosmetic_generic":    a.proxy.InjectGeneric(),
		"transparent":         a.trans != nil,
		"autostart":           autostartOn(),
	}
}

func autostartOn() bool {
	on, _ := autostart.IsEnabled()
	return on
}

// SetFeature applies and persists one dashboard toggle.
func (a *app) SetFeature(name string, on bool) bool {
	if a.proxy == nil {
		return false
	}
	switch name {
	case "ad_blocking":
		a.proxy.SetCategory(filter.CatAds, on)
		a.cfg.AdBlocking = on
	case "privacy_protection":
		a.proxy.SetCategory(filter.CatPrivacy, on)
		a.cfg.Privacy = on
	case "web_protection":
		a.proxy.SetCategory(filter.CatSecurity, on)
		a.cfg.WebProtection = on
	case "annoyances_blocking":
		a.proxy.SetCategory(filter.CatAnnoyances, on)
		a.cfg.Annoyances = on
	case "ghost_mode":
		a.proxy.SetGhost(on)
		a.cfg.GhostMode = on
	case "cosmetic_generic":
		a.proxy.SetInjectGeneric(on)
		a.cfg.CosmeticGeneric = on
	case "transparent":
		a.setTransparent(on)
	case "autostart":
		if on {
			exe, err := os.Executable()
			if err == nil {
				err = autostart.Enable(exe)
			}
			if err != nil {
				a.log.Warn("enable autostart", "err", err)
			}
		} else if err := autostart.Disable(); err != nil {
			a.log.Warn("disable autostart", "err", err)
		}
	default:
		return false
	}
	if err := a.cfg.Save(); err != nil {
		a.log.Warn("save config", "err", err)
	}
	a.log.Info("feature toggled", "name", name, "on", on)
	return true
}

// applySystemProxy routes system traffic through Adnesia — but only when its
// CA is trusted. With an untrusted CA every HTTPS connection through the proxy
// fails, which takes down the browser and every other app, so in that case we
// leave the system proxy alone.
func (a *app) applySystemProxy() {
	if !a.caTrusted {
		a.log.Warn("not setting system proxy: Adnesia's certificate is not trusted by Windows")
		return
	}
	if err := a.sp.Set(a.cfg.ProxyAddr); err != nil {
		a.log.Warn("set system proxy", "err", err)
		return
	}
	a.log.Info("system proxy set", "addr", a.cfg.ProxyAddr)
	a.startWatchdog()
}

// CATrusted reports whether Windows trusts Adnesia's CA (for the dashboard).
func (a *app) CATrusted() bool { return a.caTrusted }

// startWatchdog launches a detached helper that clears the system proxy if
// this process dies unexpectedly — so a crash never leaves the browser stuck
// on a dead proxy. No-op if one is already running.
func (a *app) startWatchdog() {
	if a.watchdog != nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "-watchdog", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	if err := cmd.Start(); err != nil {
		a.log.Warn("watchdog start failed", "err", err)
		return
	}
	a.watchdog = cmd.Process
	a.log.Info("crash watchdog started", "pid", cmd.Process.Pid)
}

// stopWatchdog kills the watchdog (used on a clean shutdown, where we restore
// the proxy ourselves and don't want the watchdog to act).
func (a *app) stopWatchdog() {
	if a.watchdog != nil {
		_ = a.watchdog.Kill()
		a.watchdog = nil
	}
}

func (a *app) OpenDashboard() {
	url := "http://" + a.cfg.DashboardAddr
	// rundll32 opens the default browser without a shell window.
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
		a.log.Warn("could not open dashboard", "url", url, "err", err)
	}
}

func waitForSignal(log *slog.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	log.Info("running headless — Ctrl+C to stop")
	sig := <-sigCh
	log.Info("shutting down", "signal", sig.String())
}

func handleBypassCommands(f flags, bp *bypass.Manager) (bool, error) {
	switch {
	case f.bypassList:
		defaults, user, added := bp.Lists()
		printList("built-in defaults (not removable)", defaults)
		printList("from config", user)
		printList("added at runtime", added)
		return true, nil
	case f.bypassAdd != "":
		if err := bp.Add(f.bypassAdd); err != nil {
			return true, err
		}
		fmt.Printf("added to passthrough list: %s\n", f.bypassAdd)
		return true, nil
	case f.bypassRemove != "":
		removed, err := bp.Remove(f.bypassRemove)
		if err != nil {
			return true, err
		}
		if removed {
			fmt.Printf("removed from passthrough list: %s\n", f.bypassRemove)
		} else {
			fmt.Printf("not a runtime-added pattern (defaults/config can't be removed here): %s\n", f.bypassRemove)
		}
		return true, nil
	}
	return false, nil
}

func handleAutostart(f flags) (bool, error) {
	switch {
	case f.autostartOn:
		exe, err := os.Executable()
		if err != nil {
			return true, err
		}
		if err := autostart.Enable(exe); err != nil {
			return true, err
		}
		fmt.Printf("login auto-start enabled: %s\n", exe)
		return true, nil
	case f.autostartOff:
		if err := autostart.Disable(); err != nil {
			return true, err
		}
		fmt.Println("login auto-start disabled")
		return true, nil
	case f.autostatus:
		on, cmd := autostart.IsEnabled()
		if on {
			fmt.Printf("login auto-start: ENABLED (%s)\n", cmd)
		} else {
			fmt.Println("login auto-start: disabled")
		}
		return true, nil
	}
	return false, nil
}

func printList(title string, items []string) {
	fmt.Printf("== %s (%d) ==\n", title, len(items))
	for _, it := range items {
		fmt.Printf("  %s\n", it)
	}
}

func doUninstall(log *slog.Logger, authority *ca.CA, noSysProxy bool) error {
	if err := authority.UninstallTrust(); err != nil {
		log.Warn("removing CA from trust store", "err", err)
	} else {
		log.Info("CA removed from trust store")
	}
	if !noSysProxy {
		if err := (&sysproxy.Controller{}).Unset(); err != nil {
			log.Warn("resetting system proxy", "err", err)
		} else {
			log.Info("system proxy reset")
		}
	}
	return nil
}
