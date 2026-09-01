package connectorhost

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const maxShellOutputBytes = 512 << 10

func ExecuteShell(ctx context.Context, input protocol.ShellInput, started func(int) error) (protocol.ShellOutput, error) {
	if input.Command == "" {
		return protocol.ShellOutput{}, errors.New("connectorhost: shell command is required")
	}
	limit := input.MaxOutputBytes
	if limit == 0 {
		limit = maxShellOutputBytes
	}
	if limit < 1 || limit > maxShellOutputBytes {
		return protocol.ShellOutput{}, fmt.Errorf("connectorhost: shell output limit must be between 1 and %d", maxShellOutputBytes)
	}
	for key, value := range input.Environment {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return protocol.ShellOutput{}, errors.New("connectorhost: shell environment is invalid")
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return protocol.ShellOutput{}, err
	}
	command := exec.CommandContext(ctx, executable, append([]string{"__airlock_shell", input.Command}, input.Arguments...)...)
	configureShellCommand(command)
	command.WaitDelay = 2 * time.Second
	command.Dir = input.WorkingDirectory
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		environment[key] = value
	}
	for key, value := range input.Environment {
		environment[key] = value
	}
	command.Env = make([]string, 0, len(environment))
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	commandInput, err := command.StdinPipe()
	if err != nil {
		return protocol.ShellOutput{}, err
	}
	budget := &shellOutputBudget{remaining: limit}
	stdout, stderr := &shellBuffer{budget: budget}, &shellBuffer{budget: budget}
	command.Stdout, command.Stderr = stdout, stderr
	err = command.Start()
	if err == nil {
		var cleanup func()
		cleanup, err = shellCommandStarted(command)
		if err == nil {
			err = started(command.Process.Pid)
		}
		if err == nil {
			err = binary.Write(commandInput, binary.BigEndian, uint64(len(input.Stdin)))
		}
		if err == nil && len(input.Stdin) > 0 {
			_, err = commandInput.Write(input.Stdin)
		}
		if err == nil {
			err = command.Wait()
			_ = commandInput.Close()
			cleanup()
		} else {
			_ = command.Cancel()
			_ = commandInput.Close()
			_ = command.Wait()
		}
	}
	output := protocol.ShellOutput{Stdout: append([]byte(nil), stdout.Bytes()...), Stderr: append([]byte(nil), stderr.Bytes()...)}
	if command.ProcessState != nil {
		output.ExitCode = command.ProcessState.ExitCode()
	} else {
		output.ExitCode = -1
	}
	if budget.overflow {
		return output, errors.New("connectorhost: shell output exceeded configured bound")
	}
	if err != nil {
		if ctx.Err() != nil {
			return output, ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return output, nil
		}
		return output, err
	}
	return output, nil
}

type shellBuffer struct {
	data   []byte
	budget *shellOutputBudget
}

type shellOutputBudget struct {
	mu        sync.Mutex
	remaining int64
	overflow  bool
}

func (b *shellBuffer) Write(value []byte) (int, error) {
	original := len(value)
	b.budget.mu.Lock()
	defer b.budget.mu.Unlock()
	if int64(len(value)) > b.budget.remaining {
		b.budget.overflow = true
		value = value[:b.budget.remaining]
	}
	b.data = append(b.data, value...)
	b.budget.remaining -= int64(len(value))
	return original, nil
}
func (b *shellBuffer) Bytes() []byte { return b.data }
