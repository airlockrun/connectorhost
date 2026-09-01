package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	connectorhost "github.com/airlockrun/connectorhost"
)

func main() {
	handled, err := runNativeService(os.Args[1:])
	if handled {
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "__airlock_shell" {
		os.Exit(connectorhost.RunShellHelper(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	global := flag.NewFlagSet("airlock-host", flag.ContinueOnError)
	global.SetOutput(stderr)
	global.Usage = func() { writeUsage(stderr) }
	stateDirectory := global.String("state-dir", "", "independent host state directory")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		writeUsage(stdout)
		return nil
	}
	if args[0] == "help" {
		if len(args) != 1 {
			return errors.New("airlock-host: help takes no arguments")
		}
		writeUsage(stdout)
		return nil
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return errors.New("airlock-host: version takes no arguments")
		}
		_, err := fmt.Fprintf(stdout, "airlock-host v%s\n", connectorhost.Version)
		return err
	}
	if args[0] == "service" {
		if *stateDirectory != "" {
			return errors.New("airlock-host: managed services use a fixed machine state directory; do not pass --state-dir")
		}
		return serviceCommand(args[1:], stdin, stdout, stderr)
	}
	if args[0] == "enroll" {
		return enrollCommand(*stateDirectory, args[1:], stdin, stdout, stderr)
	}
	if *stateDirectory == "" {
		root, err := defaultStateDirectory()
		if err != nil {
			return err
		}
		*stateDirectory = root
	}
	switch args[0] {
	case "serve":
		set := flag.NewFlagSet("serve", flag.ContinueOnError)
		set.SetOutput(stderr)
		controlPort := set.Int("control-port", connectorhost.DefaultControlPort, "TCP4 loopback control port")
		if err := set.Parse(args[1:]); err != nil {
			return err
		}
		if set.NArg() != 0 {
			return errors.New("airlock-host: serve takes only --control-port")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runHost(ctx, *stateDirectory, *controlPort)
	case "access":
		return accessCommand(*stateDirectory, args[1:], stdout)
	case "connector":
		return connectorCommand(*stateDirectory, args[1:], stdout, stderr)
	default:
		writeUsage(stderr)
		return fmt.Errorf("airlock-host: unknown command %q", args[0])
	}
}

func enrollCommand(stateDirectory string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	airlockURL, mode, err := parseEnrollmentOptions("enroll", args, stdin, stdout, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if stateDirectory != "" {
		return enrollHost(ctx, stateDirectory, airlockURL, mode, stdout)
	}
	manager, err := newNativeServiceManager()
	if err != nil {
		return err
	}
	return enrollManagedService(ctx, manager, airlockURL, mode, stdout)
}

func parseEnrollmentOptions(command string, args []string, stdin io.Reader, stdout, stderr io.Writer) (string, connectorhost.AccessMode, error) {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(stderr)
	airlockURL := set.String("airlock", "", "Airlock HTTPS origin")
	modeValue := set.String("mode", "", "remote management mode: full, update_only, or none")
	if err := set.Parse(args); err != nil {
		return "", "", err
	}
	if set.NArg() != 0 || *airlockURL == "" {
		return "", "", fmt.Errorf("airlock-host: %s requires --airlock HTTPS-origin", command)
	}
	if err := connectorhost.ValidateAirlockOrigin(*airlockURL); err != nil {
		return "", "", err
	}
	mode, err := selectEnrollmentMode(*modeValue, stdin, stdout, isInteractiveInput(stdin))
	if err != nil {
		return "", "", err
	}
	return *airlockURL, mode, nil
}

func selectEnrollmentMode(value string, input io.Reader, output io.Writer, interactive bool) (connectorhost.AccessMode, error) {
	if value != "" {
		return connectorhost.ParseAccessMode(value)
	}
	if !interactive {
		return "", errors.New("airlock-host: enrollment requires --mode full|update_only|none when input is not interactive")
	}
	_, _ = fmt.Fprintln(output, "Select the remote management mode for this host:")
	_, _ = fmt.Fprintln(output, "  1) full        allow install, update, remove, rollback, and shell")
	_, _ = fmt.Fprintln(output, "  2) update_only allow update and rollback of existing connectors")
	_, _ = fmt.Fprintln(output, "  3) none        disable remote management; connector jobs still run")
	scanner := bufio.NewScanner(input)
	for {
		_, _ = fmt.Fprint(output, "Mode [1/2/3]: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", errors.New("airlock-host: no enrollment mode selected")
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "1", "full":
			return connectorhost.AccessFull, nil
		case "2", "update_only":
			return connectorhost.AccessUpdateOnly, nil
		case "3", "none":
			return connectorhost.AccessNone, nil
		default:
			_, _ = fmt.Fprintln(output, "Enter 1, 2, 3, full, update_only, or none.")
		}
	}
}

func isInteractiveInput(input io.Reader) bool {
	file, ok := input.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func accessCommand(root string, args []string, stdout io.Writer) error {
	if len(args) == 1 && args[0] == "get" {
		return controlFirst(root, true,
			func(ctx context.Context, client *connectorhost.LocalControlClient) error {
				mode, err := client.Access(ctx)
				if err == nil {
					_, err = fmt.Fprintln(stdout, mode)
				}
				return err
			},
			func(_ context.Context, _ *connectorhost.Host, store *connectorhost.Store) error {
				_, err := fmt.Fprintln(stdout, store.AccessMode())
				return err
			})
	}
	if len(args) == 2 && args[0] == "set" {
		mode, err := connectorhost.ParseAccessMode(args[1])
		if err != nil {
			return err
		}
		return controlFirst(root, false,
			func(ctx context.Context, client *connectorhost.LocalControlClient) error {
				return client.SetAccess(ctx, mode)
			},
			func(_ context.Context, _ *connectorhost.Host, store *connectorhost.Store) error {
				return store.SetAccessMode(mode)
			})
	}
	return errors.New("airlock-host: access requires get or set <full|update_only|none>")
}

func connectorCommand(root string, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("airlock-host: connector requires install, update, rollback, remove, list, or status")
	}
	switch args[0] {
	case "install":
		if len(args) < 2 {
			return errors.New("airlock-host: connector install requires a local binary path")
		}
		set := flag.NewFlagSet("connector install", flag.ContinueOnError)
		set.SetOutput(stderr)
		name := set.String("name", "", "connector display name")
		settingsPath := set.String("settings", "", "JSON settings file")
		digest := set.String("sha256", "", "optional lowercase SHA-256")
		if err := set.Parse(args[2:]); err != nil {
			return err
		}
		if set.NArg() != 0 {
			return errors.New("airlock-host: connector install accepts one local binary path")
		}
		source, err := resolveSource(args[1])
		if err != nil {
			return err
		}
		settings, err := readSettings(*settingsPath)
		if err != nil {
			return err
		}
		installationID, err := connectorhost.NewInstallationID()
		if err != nil {
			return err
		}
		request := connectorhost.LocalInstallRequest{InstallationID: installationID, SourcePath: source, DisplayName: *name, ExpectedSHA256: *digest, Settings: settings}
		return controlFirst(root, false,
			func(ctx context.Context, client *connectorhost.LocalControlClient) error {
				response, err := client.InstallFile(ctx, request)
				if err == nil {
					_, err = fmt.Fprintln(stdout, response.InstallationID)
				}
				return err
			},
			func(ctx context.Context, host *connectorhost.Host, _ *connectorhost.Store) error {
				response, err := host.LocalInstall(ctx, request)
				if err == nil {
					_, err = fmt.Fprintln(stdout, response.InstallationID)
				}
				return err
			})
	case "update":
		if len(args) < 3 {
			return errors.New("airlock-host: connector update requires an installation ID and local binary path")
		}
		set := flag.NewFlagSet("connector update", flag.ContinueOnError)
		set.SetOutput(stderr)
		settingsPath := set.String("settings", "", "replacement JSON settings file")
		digest := set.String("sha256", "", "optional lowercase SHA-256")
		if err := set.Parse(args[3:]); err != nil {
			return err
		}
		if set.NArg() != 0 {
			return errors.New("airlock-host: connector update accepts one installation ID and one local binary path")
		}
		source, err := resolveSource(args[2])
		if err != nil {
			return err
		}
		settings, err := readSettings(*settingsPath)
		if err != nil {
			return err
		}
		request := connectorhost.LocalUpdateRequest{InstallationID: args[1], SourcePath: source, ExpectedSHA256: *digest, Settings: settings}
		return controlFirst(root, false,
			func(ctx context.Context, client *connectorhost.LocalControlClient) error {
				return client.UpdateFile(ctx, request)
			},
			func(ctx context.Context, host *connectorhost.Host, _ *connectorhost.Store) error {
				return host.LocalUpdate(ctx, request)
			})
	case "rollback", "remove":
		if len(args) != 2 {
			return fmt.Errorf("airlock-host: connector %s requires an installation ID", args[0])
		}
		return controlFirst(root, false,
			func(ctx context.Context, client *connectorhost.LocalControlClient) error {
				if args[0] == "rollback" {
					return client.Rollback(ctx, args[1])
				}
				return client.Remove(ctx, args[1])
			},
			func(ctx context.Context, host *connectorhost.Host, _ *connectorhost.Store) error {
				if args[0] == "rollback" {
					return host.Rollback(ctx, args[1])
				}
				return host.Remove(ctx, args[1])
			})
	case "list":
		if len(args) != 1 {
			return errors.New("airlock-host: connector list takes no arguments")
		}
		return statusCommand(root, "", false, stdout)
	case "status":
		id, jsonOutput, err := parseStatusArguments(args[1:])
		if err != nil {
			return err
		}
		return statusCommand(root, id, jsonOutput, stdout)
	default:
		return errors.New("airlock-host: connector requires install, update, rollback, remove, list, or status")
	}
}

func statusCommand(root, id string, jsonOutput bool, stdout io.Writer) error {
	printStatuses := func(statuses []connectorhost.LocalConnectorStatus) error {
		if jsonOutput {
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(statuses)
		}
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(writer, "ID\tNAME\tVERSION\tREADINESS\tROLLBACK\tSHA256"); err != nil {
			return err
		}
		for _, status := range statuses {
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%t\t%s\n", status.InstallationID, status.DisplayName, status.ArtifactVersion, status.Readiness, status.HasRollback, status.ArtifactDigest); err != nil {
				return err
			}
		}
		return writer.Flush()
	}
	return controlFirst(root, true,
		func(ctx context.Context, client *connectorhost.LocalControlClient) error {
			statuses, err := client.Statuses(ctx, id)
			if err == nil {
				err = printStatuses(statuses)
			}
			return err
		},
		func(_ context.Context, host *connectorhost.Host, _ *connectorhost.Store) error {
			statuses, err := host.LocalStatuses(id)
			if err == nil {
				err = printStatuses(statuses)
			}
			return err
		})
}

func controlFirst(root string, readOnly bool, remote func(context.Context, *connectorhost.LocalControlClient) error, direct func(context.Context, *connectorhost.Host, *connectorhost.Store) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var controlErr error
	runDirect := func(store *connectorhost.Store) error {
		host := connectorhost.NewHost(store, nil)
		host.CleanupStaging()
		err := direct(ctx, host, store)
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		closeErr := host.Close(closeCtx)
		closeCancel()
		storeErr := store.Close()
		return errors.Join(err, closeErr, storeErr)
	}
	if client, err := connectorhost.NewLocalControlClient(root); err == nil {
		controlErr = remote(ctx, client)
		var apiError *connectorhost.LocalControlAPIError
		if !readOnly || controlErr == nil || errors.As(controlErr, &apiError) {
			return controlErr
		}
	} else {
		controlErr = err
	}
	store, lockErr := connectorhost.OpenStore(root)
	if lockErr == nil {
		return runDirect(store)
	}
	if !errors.Is(lockErr, connectorhost.ErrStateLocked) {
		return lockErr
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), lockErr)
		case <-timer.C:
		}
		client, err := connectorhost.NewLocalControlClient(root)
		if err != nil {
			controlErr = err
		} else {
			controlErr = remote(ctx, client)
			var apiError *connectorhost.LocalControlAPIError
			if !readOnly || controlErr == nil || errors.As(controlErr, &apiError) {
				return controlErr
			}
		}
		store, err := connectorhost.OpenStore(root)
		if err == nil {
			return runDirect(store)
		}
		if !errors.Is(err, connectorhost.ErrStateLocked) {
			return err
		}
	}
	return errors.Join(errors.New("airlock-host: state directory is locked and no local control server answered"), lockErr, controlErr)
}

func readSettings(path string) (json.RawMessage, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, protocol.MaxJobPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > protocol.MaxJobPayloadBytes || !json.Valid(body) {
		return nil, errors.New("airlock-host: settings must be bounded valid JSON")
	}
	return body, nil
}

func resolveSource(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}

func parseStatusArguments(args []string) (string, bool, error) {
	var id string
	jsonOutput := false
	for _, argument := range args {
		if argument == "--json" {
			if jsonOutput {
				return "", false, errors.New("airlock-host: connector status received --json more than once")
			}
			jsonOutput = true
			continue
		}
		if id != "" {
			return "", false, errors.New("airlock-host: connector status accepts at most one installation ID")
		}
		id = argument
	}
	return id, jsonOutput, nil
}

func defaultStateDirectory() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "airlock", "host"), nil
}

func runHost(ctx context.Context, stateDirectory string, controlPort int) error {
	store, err := connectorhost.OpenStore(stateDirectory)
	if err != nil {
		return err
	}
	defer store.Close()
	return connectorhost.NewHost(store, nil).ServeControl(ctx, controlPort)
}

func enrollHost(ctx context.Context, stateDirectory, airlockURL string, mode connectorhost.AccessMode, output io.Writer) error {
	store, err := connectorhost.OpenStore(stateDirectory)
	if err == nil {
		defer store.Close()
		persistedURL, credential := store.Credentials()
		if persistedURL != "" || credential != "" {
			return errors.New("airlock-host: host is already enrolled")
		}
		return connectorhost.Enroll(ctx, store, airlockURL, mode, output)
	}
	if !errors.Is(err, connectorhost.ErrStateLocked) {
		return err
	}
	return controlFirst(stateDirectory, false,
		func(ctx context.Context, client *connectorhost.LocalControlClient) error {
			return client.Enroll(ctx, airlockURL, mode, func(prompt connectorhost.EnrollmentPrompt) error {
				_, err := fmt.Fprintf(output, "Open: %s\nCode: %s\n", prompt.VerificationURL, prompt.UserCode)
				return err
			})
		},
		func(context.Context, *connectorhost.Host, *connectorhost.Store) error {
			return errors.New("airlock-host: serving host stopped during enrollment startup")
		})
}

func writeUsage(output io.Writer) {
	_, _ = fmt.Fprint(output, `Airlock Connector Host

Managed host quick start:
  sudo airlock-host enroll --airlock https://airlock.example
  sudo airlock-host enroll --airlock https://airlock.example --mode full

The interactive enrollment flow asks for full, update_only, or none. Use
--mode for noninteractive enrollment.

Usage:
  airlock-host enroll --airlock HTTPS-ORIGIN [--mode MODE]
  airlock-host access get
  airlock-host access set full|update_only|none
  airlock-host connector <install|update|rollback|remove|list|status>
  airlock-host service <install|start|stop|status|uninstall|enroll>
  airlock-host version

Standalone mode:
  airlock-host --state-dir DIR enroll --airlock HTTPS-ORIGIN [--mode MODE]
  airlock-host --state-dir DIR serve [--control-port PORT]

Options:
  --state-dir DIR  use an independent standalone state directory
  -h, --help       show this help
`)
}
