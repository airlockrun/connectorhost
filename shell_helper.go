package connectorhost

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

func RunShellHelper(arguments []string, input io.Reader, output, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		_, _ = fmt.Fprintln(errorOutput, "connectorhost: shell helper requires a command")
		return 1
	}
	var inputSize uint64
	if err := binary.Read(input, binary.BigEndian, &inputSize); err != nil {
		return 1
	}
	if inputSize > 1<<20 {
		_, _ = fmt.Fprintln(errorOutput, "connectorhost: shell input exceeds configured bound")
		return 1
	}
	stdin := make([]byte, inputSize)
	if _, err := io.ReadFull(input, stdin); err != nil {
		return 1
	}
	command := exec.Command(arguments[0], arguments[1:]...)
	command.Stdin = bytes.NewReader(stdin)
	command.Stdout = output
	command.Stderr = errorOutput
	if err := command.Start(); err != nil {
		_, _ = fmt.Fprintln(errorOutput, err)
		return 1
	}
	parentGone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, input)
		close(parentGone)
	}()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case err := <-waited:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		if err != nil {
			_, _ = fmt.Fprintln(errorOutput, err)
			return 1
		}
		return 0
	case <-parentGone:
		_ = terminateShellHelper(command)
		<-waited
		return 1
	}
}
