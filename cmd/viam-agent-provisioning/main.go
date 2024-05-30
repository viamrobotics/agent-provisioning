package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

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
	if err != nil {
		log.Fatal(err)
	}

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

	ctx := setupExitSignalHandling()
	defer activeBackgroundWorkers.Wait()

	// Manufacturer settings from agent-provisioning.json
	pCfg, err := provisioning.LoadConfig(provisioning.DefaultConf, opts.ProvisioningConfig)
	if err != nil {
		log.Error(errw.Wrapf(err, "error loading %s, using defaults", opts.ProvisioningConfig))
	}

	// User settings from the "attributes" section of the cloud config (passed from parent agent via json file)
	cfg, err := provisioning.LoadConfig(*pCfg, opts.Config)
	if err != nil {
		log.Error(errw.Wrapf(err, "error loading %s, using defaults", opts.Config))
	}

	nm, err := netman.NewNMWrapper(ctx, log, pCfg, opts.AppConfig)
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

	// this will loop indefinitely until context cancellation or serious error
	if err := nm.StartMonitoring(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error(err)
	}

	log.Info("agent-provisioning subsystem exiting")
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
				log.Info("exit signal received")
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
