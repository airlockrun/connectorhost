package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	connectorhost "github.com/airlockrun/connectorhost"
)

const (
	nativeServiceName        = "AirlockHost"
	nativeServiceDisplayName = "Airlock Connector Host"
)

type nativeServiceState string

const (
	serviceNotInstalled nativeServiceState = "not-installed"
	serviceStopped      nativeServiceState = "stopped"
	serviceStartPending nativeServiceState = "start-pending"
	serviceStopPending  nativeServiceState = "stop-pending"
	serviceRunning      nativeServiceState = "running"
	servicePaused       nativeServiceState = "paused"
	serviceUnknown      nativeServiceState = "unknown"
)

type nativeServiceStatus struct {
	State                   nativeServiceState
	PID                     uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
}

type nativeServiceManager interface {
	Install(context.Context) error
	Start(context.Context) error
	Stop(context.Context) error
	Status(context.Context) (nativeServiceStatus, error)
	Uninstall(context.Context) error
	StateDirectory() string
}

func serviceCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return serviceUsageError()
	}
	manager, err := newNativeServiceManager()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "install":
		if len(args) != 1 {
			return errors.New("airlock-host: service install takes no arguments")
		}
		if err := manager.Install(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, `installed
Next:
  airlock-host service start
  airlock-host enroll --airlock https://airlock.example`)
		return err
	case "start":
		if len(args) != 1 {
			return errors.New("airlock-host: service start takes no arguments")
		}
		if err := manager.Start(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "running")
		return err
	case "stop":
		if len(args) != 1 {
			return errors.New("airlock-host: service stop takes no arguments")
		}
		if err := manager.Stop(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "stopped")
		return err
	case "status":
		if len(args) != 1 {
			return errors.New("airlock-host: service status takes no arguments")
		}
		status, err := manager.Status(ctx)
		if err != nil {
			return err
		}
		if status.PID != 0 {
			_, err = fmt.Fprintf(stdout, "%s\t%d\n", status.State, status.PID)
		} else if status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
			_, err = fmt.Fprintf(stdout, "%s\twin32=%d\tservice=%d\n", status.State, status.Win32ExitCode, status.ServiceSpecificExitCode)
		} else {
			_, err = fmt.Fprintln(stdout, status.State)
		}
		return err
	case "uninstall":
		if len(args) != 1 {
			return errors.New("airlock-host: service uninstall takes no arguments")
		}
		if err := manager.Uninstall(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "uninstalled")
		return err
	case "enroll":
		airlockURL, mode, err := parseEnrollmentOptions("service enroll", args[1:], stdin, stdout, stderr)
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		return enrollManagedService(ctx, manager, airlockURL, mode, stdout)
	default:
		return serviceUsageError()
	}
}

func enrollManagedService(ctx context.Context, manager nativeServiceManager, airlockURL string, mode connectorhost.AccessMode, stdout io.Writer) error {
	status, err := manager.Status(ctx)
	if err != nil {
		return err
	}
	if status.State == serviceNotInstalled {
		return errors.New("airlock-host: managed service is not installed; install the Linux package or run 'airlock-host service install'")
	}
	if status.State == servicePaused {
		return errors.New("airlock-host: managed service is paused; resume it before enrollment")
	}
	if status.State != serviceRunning {
		if status.State != serviceStartPending {
			if err := requireUnenrolledState(manager.StateDirectory()); err != nil {
				return err
			}
		}
		if err := manager.Start(ctx); err != nil {
			return err
		}
	}
	return enrollHost(ctx, manager.StateDirectory(), airlockURL, mode, stdout)
}

func requireUnenrolledState(stateDirectory string) error {
	store, err := connectorhost.OpenStore(stateDirectory)
	if err != nil {
		return err
	}
	defer store.Close()
	airlockURL, credential := store.Credentials()
	if airlockURL != "" || credential != "" {
		return errors.New("airlock-host: host is already enrolled")
	}
	return nil
}

func serviceUsageError() error {
	return errors.New("usage: airlock-host service <install|start|stop|status|uninstall|enroll>")
}
