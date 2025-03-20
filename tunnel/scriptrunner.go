/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func runScriptCommand(command, interfaceName string) error {
	if len(command) == 0 {
		return nil
	}
	if !conf.AdminBool("DangerousScriptExecution") {
		log.Printf("Skipping execution of script, because dangerous script execution is safely disabled: %#q", command)
		return nil
	}
	log.Printf("Executing: %#q", command)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get COMSPEC environment variable with fallback
	comspec, exists := os.LookupEnv("COMSPEC")
	if !exists || len(comspec) == 0 {
		system32, err := windows.GetSystemDirectory()
		if err != nil {
			return fmt.Errorf("failed to get system directory: %w", err)
		}
		comspec = filepath.Join(system32, "cmd.exe")
	}

	// Open devNull with proper error handling
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open devNull: %w", err)
	}
	defer devNull.Close()

	// Create pipe with proper error handling
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}
	defer reader.Close()
	// We'll close writer after starting the process

	// Prepare process attributes with improved security
	procAttr := &os.ProcAttr{
		Files: []*os.File{devNull, writer, writer},
		Env:   append(os.Environ(), "WIREGUARD_TUNNEL_NAME="+interfaceName),
		Sys: &syscall.SysProcAttr{
			HideWindow:    true,
			CmdLine:       fmt.Sprintf("cmd /c %s", command),
			CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
		},
	}

	// Start process with context
	process, err := os.StartProcess(comspec, nil, procAttr)
	if err != nil {
		writer.Close()
		return fmt.Errorf("failed to start process: %w", err)
	}
	writer.Close()

	// Launch a goroutine to read process output with context
	outputChan := make(chan string, 100)
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case outputChan <- scanner.Text():
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading process output: %v", err)
		}
	}()

	// Process output with timeout
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case output, ok := <-outputChan:
				if !ok {
					return
				}
				log.Printf("cmd> %s", output)
			}
		}
	}()

	// Wait for process to finish with context
	done := make(chan error, 1)
	var procState *os.ProcessState
	go func() {
		var err error
		procState, err = process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("process wait failed: %w", err)
		}
	case <-ctx.Done():
		// Kill process group to ensure all child processes are terminated
		if err := process.Kill(); err != nil {
			log.Printf("Warning: failed to kill process: %v", err)
		}
		return fmt.Errorf("process timed out after 30 seconds")
	}

	if procState.ExitCode() == 0 {
		return nil
	}

	log.Printf("Command error exit status: %d", procState.ExitCode())
	return windows.ERROR_GENERIC_COMMAND_FAILED
}
