package main

import (
	"bytes"
	"fmt"
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"

	netman "github.com/viamrobotics/agent-provisioning/networkmanager"
	"github.com/viamrobotics/agent-provisioning"
)

var (
	// only changed/set at startup, so no mutex.
	log = golog.NewDevelopmentLogger("agent-provisioning")
	activeBackgroundWorkers sync.WaitGroup
)

func main() {
	ctx := setupExitSignalHandling()

	var opts struct {
		Config  string `default:"/opt/viam/etc/agent-provisioning.json"              description:"Path to config file" long:"config" short:"c"`
		AppConfig    string `default:"/etc/viam.json"              description:"Path to main viam cloud (app) config file" long:"app" short:"a"`
		ProvisioningConfig    string `default:"/etc/viam-provisioning.json"              description:"Path to provisioning (customization) config file" long:"provisioning" short:"p"`
		Debug   bool   `description:"Enable debug logging"    long:"debug"                      short:"d"`
		Help    bool   `description:"Show this help message"  long:"help"                       short:"h"`
		Version bool   `description:"Show version"            long:"version"                    short:"v"`
		//Install bool   `description:"Install systemd service" long:"install"`
	}

	parser := flags.NewParser(&opts, flags.IgnoreUnknown)
	parser.Usage = "runs as a background service and manages updates and the process lifecycle for viam-server."

	_, err := parser.Parse()
	exitIfError(err)

	if opts.Help {
		var b bytes.Buffer
		parser.WriteHelp(&b)
		//nolint:forbidigo
		fmt.Println(b.String())
		return
	}

	if opts.Version {
		fmt.Printf("Version: %s\nGit Revision: %s\n", provisioning.GetVersion(), provisioning.GetRevision())
		return
	}

	if opts.Debug {
		log = golog.NewDebugLogger("agent-provisioning")
	}



	pCfg, err := provisioning.LoadProvisioningConfig(opts.ProvisioningConfig)
	if err != nil {
		log.Warn(err)
	}

	cfg, err := provisioning.LoadConfig(opts.Config)
	if err != nil {
		log.Warn(err)
	}

	// If user settings override the hotspot password, use that instead
	if cfg.HotspotPassword != "" {
		pCfg.HotspotPassword = cfg.HotspotPassword
	}

	nm, err := netman.NewNMWrapper(log, pCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer nm.Close()

	for _, network := range cfg.Networks {
		log.Debugf("adding/updating NetworkManager configuration for %s", network.SSID)
		if err := nm.AddOrUpdateConnection(network); err != nil {
			log.Error(errw.Wrapf(err, "error adding network %s", network.SSID))
		}
	}

	// exact text is important, the parent process will watch for this line to indicate startup is successful
	log.Info("agent-provisioning startup complete")

	var prevError error

	// initial scan
	nm.WifiScan(ctx)

	var settingsChan <-chan netman.WifiSettings
	for {
		select {
		case <-ctx.Done():
			activeBackgroundWorkers.Wait()
			return
		case <-time.After(time.Second * 15):
		}

		online, err := nm.CheckOnline()
		if err != nil {
			log.Error(err)
		}

		if online {
			nm.MarkSSIDsTried()
		}

		// check if we have a readable cloud config, if not, we need to bootstrap
		_, err = os.ReadFile(opts.AppConfig)

		configured := err == nil

		log.Debugf("online: %t, config_present: %t", online, configured)
		if online && configured {
			continue
		}

		// offline logic
		nm.WifiScan(ctx)
		bs, bsTime := nm.GetBootstrap()
		 _, _, lastOnline := nm.GetOnline()
		// not in bootstrap mode, so start it if not configure OR as long as we've been OUT of bootstrap for two minutes to try connections
		if !bs && (!configured || time.Now().After(bsTime.Add(time.Second)) && time.Now().After(lastOnline.Add(time.Minute * 2))) {
			log.Debug("starting bootstrap")
			settingsChan, err = nm.StartBootstrap(ctx, prevError)
			if err != nil {
				log.Error(err)
			}
			bs = true
		}

		if !bs {
			continue
		}

		// in bootstrap mode, wait for settings from user OR timeout
		log.Debug("bootstrap waiting")

		var activateSSID string
		// will exit bootstrap after the select by default
		shouldStopBS := true
		select {
		case settings := <-settingsChan:
			// non-empty settings mean add a new network and exit bootstrap mode
			if settings.SSID != "" && settings.PSK != "" {
				log.Debug("settings recieved")
				err := nm.AddOrUpdateConnection(provisioning.NetworkConfig{
					Type: "wifi",
					SSID: settings.SSID,
					PSK: settings.PSK,
					Priority: 100,
				})
				if err != nil {
					prevError = err
					log.Error(err)
					continue
				}
				activateSSID = settings.SSID
			}
			// empty settings mean a known SSID newly became visible, but we don't exit if someone's in the portal
			if !time.Now().After(nm.GetLastInteraction().Add(time.Minute * 5)) {
				shouldStopBS = false
			}
		case <-ctx.Done():
			log.Debug("main context cancelled")
		case <-time.After(10 * time.Minute):
			// don't exit bootstrap mode if someone is active in the portal
			if !time.Now().After(nm.GetLastInteraction().Add(time.Minute * 5)) {
				shouldStopBS = false
			}
			log.Debug("10 minute timeout")
		}

		if shouldStopBS {
			log.Debug("bootstrap stopping")
			err = nm.StopBootstrap()
			if err != nil {
				log.Error(err)
			}
		}
		// force activating the SSID to save time (or if it was somehow manually disabled)
		if activateSSID != "" {
			nm.ActivateConnection(activateSSID)
		}
	}
}

func setupExitSignalHandling() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 16)
	activeBackgroundWorkers.Add(1)
	go func() {
		defer activeBackgroundWorkers.Done()
		defer cancel()
		for {
			sig := <-sigChan
			switch sig {
			// things we exit for
			case os.Interrupt:
				fallthrough
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGABRT:
				fallthrough
			case syscall.SIGTERM:
				log.Info("exiting")
				signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGABRT) // keeping SIGQUIT for stack trace debugging
				return

			// this will eventually be handled elsewhere as a restart, not exit
			case syscall.SIGHUP:

			// ignore SIGURG entirely, it's used for real-time scheduling notifications
			case syscall.SIGURG:

			// used by parent viam-agent for healthchecks
			case syscall.SIGUSR1:
				fmt.Println("HEALTHY")

			// log everything else
			default:
				log.Debugw("received unknown signal", "signal", sig)
			}
		}
	}()

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT, syscall.SIGUSR1)
	return ctx
}

func exitIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
