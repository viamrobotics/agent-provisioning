package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/edaniels/golog"
	"github.com/jessevdk/go-flags"
	errw "github.com/pkg/errors"

	"github.com/viamrobotics/agent-provisioning"
	netman "github.com/viamrobotics/agent-provisioning/networkmanager"
)

var (
	// only changed/set at startup, so no mutex.
	log = golog.NewDevelopmentLogger("agent-provisioning")

	activeBackgroundWorkers sync.WaitGroup
)

func main() {
	ctx := setupExitSignalHandling()
	defer activeBackgroundWorkers.Wait()

	//nolint:lll
	var opts struct {
		Config             string `default:"/opt/viam/etc/agent-provisioning.json" description:"Path to config file"                              long:"config"       short:"c"`
		AppConfig          string `default:"/etc/viam.json"                        description:"Path to main viam cloud (app) config file"        long:"app"          short:"a"`
		ProvisioningConfig string `default:"/etc/viam-provisioning.json"           description:"Path to provisioning (customization) config file" long:"provisioning" short:"p"`
		Debug              bool   `description:"Enable debug logging"              long:"debug"                                                   short:"d"`
		Help               bool   `description:"Show this help message"            long:"help"                                                    short:"h"`
		Version            bool   `description:"Show version"                      long:"version"                                                 short:"v"`
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
		//nolint:forbidigo
		fmt.Printf("Version: %s\nGit Revision: %s\n", provisioning.GetVersion(), provisioning.GetRevision())
		return
	}

	if opts.Debug {
		log = golog.NewDebugLogger("agent-provisioning")
	}

	pCfg, err := provisioning.LoadProvisioningConfig(opts.ProvisioningConfig)
	if err != nil {
		log.Error(errw.Wrapf(err, "error loading %s, using defaults", opts.ProvisioningConfig))
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
		log.Error(err)
		return
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

	// initial scan
	if err := nm.WifiScan(ctx); err != nil {
		log.Error(err)
	}

	var settingsChan <-chan *provisioning.UserInput
	for {
		if !provisioning.HealthySleep(ctx, time.Second*15) {
			return
		}

		online, err := nm.CheckOnline()
		if err != nil {
			log.Error(err)
		}

		if online {
			nm.MarkSSIDsTried()
		}

		configured := nm.CheckConfigured(opts.AppConfig)

		log.Debugf("online: %t, config_present: %t", online, configured)

		// restart the loop if everything is good
		if online && configured {
			continue
		}

		// provisioning mode logic starts here for when not online and configured
		if err := nm.WifiScan(ctx); err != nil {
			log.Error(err)
		}
		provisioningMode, provisioningTime := nm.GetProvisioning()
		_, _, lastOnline := nm.GetOnline()
		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been OUT of provisioning for two minutes to try connections
		if !provisioningMode &&
			(!configured || time.Now().After(provisioningTime.Add(time.Second)) && time.Now().After(lastOnline.Add(time.Minute*2))) {
			log.Debug("starting provisioning mode")
			settingsChan, err = nm.StartProvisioning(ctx)
			if err != nil {
				log.Error(errw.Wrap(err, "error starting provisioning mode"))
				continue
			}
			provisioningMode = true
		}

		if !provisioningMode {
			continue
		}

		// in provisioning mode, wait for settings from user OR timeout
		log.Debug("provisioning mode ready, waiting for user input")

		var activateSSID string
		// will exit provisioning after the select by default
		shouldStopProvisioning := true
		select {
		case settings := <-settingsChan:
			if settings == nil && !time.Now().After(nm.GetLastInteraction().Add(time.Minute*5)) {
				// empty settings mean a known SSID newly became visible, but we don't exit if someone's in the portal
				shouldStopProvisioning = false
			}

			// non-empty settings mean add a new network and exit provisioning mode
			if settings != nil && settings.SSID != "" {
				log.Debug("wifi settings received")
				err := nm.AddOrUpdateConnection(provisioning.NetworkConfig{
					Type:     "wifi",
					SSID:     settings.SSID,
					PSK:      settings.PSK,
					Priority: 100,
				})
				if err != nil {
					nm.AppendError(err)
					log.Error(err)
					continue
				}
				activateSSID = settings.SSID
			}

			if settings != nil && (settings.RawConfig != "" || settings.PartID != "") {
				log.Debug("device config received")
				err := provisioning.WriteDeviceConfig(opts.AppConfig, settings)
				if err != nil {
					nm.AppendError(err)
					log.Error(err)
					continue
				}
			}

		case <-ctx.Done():
			log.Debug("main context cancelled")
		case <-time.After(10 * time.Minute):
			// don't exit provisioning mode if someone is active in the portal
			if !time.Now().After(nm.GetLastInteraction().Add(time.Minute * 5)) {
				shouldStopProvisioning = false
			}
			log.Debug("10 minute timeout")
		}

		if shouldStopProvisioning {
			log.Debug("provisioning mode stopping")
			err = nm.StopProvisioning()
			if err != nil {
				log.Error(err)
			}
		}
		// force activating the SSID to save time (or if it was somehow manually disabled)
		if activateSSID != "" {
			if err := nm.ActivateConnection(ctx, activateSSID); err != nil {
				nm.AppendError(err)
				log.Error(err)
			}
		}
	}
}

func setupExitSignalHandling() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 16)

	healthcheckRequest := &atomic.Bool{}
	ctx = context.WithValue(ctx, provisioning.HCReqKey, healthcheckRequest)

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
				healthcheckRequest.Store(true)

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
