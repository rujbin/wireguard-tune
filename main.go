/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/tunnel"
	"golang.zx2c4.com/wireguard/windows/ui"
	"golang.zx2c4.com/wireguard/windows/updater"
)

const (
	uiTimeoutSeconds = 30
	uiCheckInterval  = 100 * time.Millisecond
)

func setLogFile() error {
	logHandle, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if logHandle == 0 || err != nil {
		logHandle, err = windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	}
	if logHandle == 0 || err != nil {
		log.SetOutput(io.Discard)
		return nil
	}
	log.SetOutput(os.NewFile(uintptr(logHandle), "stderr"))
	return nil
}

func fatal(v ...any) {
	if log.Writer() == io.Discard {
		windows.MessageBox(0, windows.StringToUTF16Ptr(fmt.Sprint(v...)), windows.StringToUTF16Ptr(l18n.Sprintf("Error")), windows.MB_ICONERROR)
		os.Exit(1)
	} else {
		log.Fatal(append([]any{l18n.Sprintf("Error: ")}, v...))
	}
}

func fatalf(format string, v ...any) {
	fatal(l18n.Sprintf(format, v...))
}

func info(title, format string, v ...any) {
	if log.Writer() == io.Discard {
		windows.MessageBox(0, windows.StringToUTF16Ptr(l18n.Sprintf(format, v...)), windows.StringToUTF16Ptr(title), windows.MB_ICONINFORMATION)
	} else {
		log.Printf(title+":\n"+format, v...)
	}
}

func usage() {
	flags := [...]string{
		l18n.Sprintf("(no argument): elevate and install manager service"),
		"/installmanagerservice",
		"/installtunnelservice CONFIG_PATH",
		"/uninstallmanagerservice",
		"/uninstalltunnelservice TUNNEL_NAME",
		"/managerservice",
		"/tunnelservice CONFIG_PATH",
		"/ui CMD_READ_HANDLE CMD_WRITE_HANDLE CMD_EVENT_HANDLE LOG_MAPPING_HANDLE",
		"/dumplog [/tail]",
		"/update",
		"/removedriver",
	}
	
	// Pre-allocate capacity for better performance
	builder := strings.Builder{}
	builder.Grow(len(flags) * 50) // Approximate size per flag
	
	for _, flag := range flags {
		builder.WriteString(fmt.Sprintf("    %s\n", flag))
	}
	info(l18n.Sprintf("Command Line Options"), "Usage: %s [\n%s]", os.Args[0], builder.String())
	os.Exit(1)
}

func checkForWow64() {
	var b bool
	var err error
	var processMachine, nativeMachine uint16
	err = windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine)
	if err == nil {
		b = processMachine != pe.IMAGE_FILE_MACHINE_UNKNOWN
	} else if !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		fatalf("Konnte nicht feststellen, ob der Prozess unter WOW64 läuft: %v", err)
		return
	} else {
		var wow64Err error
		wow64Err = windows.IsWow64Process(windows.CurrentProcess(), &b)
		if wow64Err != nil {
			fatalf("Konnte nicht feststellen, ob der Prozess unter WOW64 läuft: %v", wow64Err)
		}
	}
	if b {
		fatalf("Sie müssen die native Version von WireGuard auf diesem Computer verwenden.")
	}
}

func checkForAdminGroup() {
	// This is not a security check, but rather a user-confusion one.
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		fatalf("Konnte das Token des aktuellen Prozesses nicht öffnen: %v", err)
	}
	defer processToken.Close()
	if !elevate.TokenIsElevatedOrElevatable(processToken) {
		fatalf("WireGuard kann nur von Benutzern verwendet werden, die Mitglied der Gruppe %s sind.", elevate.AdminGroupName())
	}
}

func checkForAdminDesktop() {
	adminDesktop, err := elevate.IsAdminDesktop()
	if !adminDesktop && err == nil {
		fatalf("WireGuard läuft, aber die Benutzeroberfläche ist nur von Desktops der Gruppe %s zugänglich.", elevate.AdminGroupName())
	}
}

func execElevatedManagerServiceInstaller() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	err = elevate.ShellExecute(path, "/installmanagerservice", "", windows.SW_SHOW)
	if err != nil && err != windows.ERROR_CANCELLED {
		return err
	}
	os.Exit(0)
	return windows.ERROR_UNHANDLED_EXCEPTION // Not reached
}

func pipeFromHandleArgument(handleStr string) (*os.File, error) {
	handleInt, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("ungültiges Handle: %w", err)
	}
	file := os.NewFile(uintptr(handleInt), "pipe")
	if file == nil {
		return nil, fmt.Errorf("Fehler beim Erstellen der Datei aus dem Handle")
	}
	return file, nil
}

func main() {
	// Set DLL directory restrictions first for security
	if err := windows.SetDllDirectory(""); err != nil {
		panic("Fehler beim Setzen des DLL-Verzeichnisses")
	}
	if err := windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		panic("Fehler beim Einschränken des DLL-Suchpfads")
	}

	if err := setLogFile(); err != nil {
		panic(fmt.Sprintf("Fehler beim Setzen der Log-Datei: %v", err))
	}
	checkForWow64()

	if len(os.Args) <= 1 {
		if ui.RaiseUI() {
			return
		}
		checkForAdminGroup()
		if err := execElevatedManagerServiceInstaller(); err != nil {
			fatal(err)
		}
		return
	}

	// Use a map for faster command lookup
	commandHandlers := map[string]func() error{
		"/installmanagerservice": func() error {
			if len(os.Args) != 2 {
				usage()
			}
			go ui.WaitForRaiseUIThenQuit()
			if err := manager.InstallManager(); err != nil {
				if err == manager.ErrManagerAlreadyRunning {
					checkForAdminDesktop()
				}
				return err
			}
			checkForAdminDesktop()
			
			// Better timeout handling with channel
			done := make(chan struct{})
			go func() {
				time.Sleep(uiTimeoutSeconds * time.Second)
				close(done)
			}()
			
			// Wait for either UI to appear or timeout
			ticker := time.NewTicker(uiCheckInterval)
			defer ticker.Stop()
			
			for {
				select {
				case <-done:
					return fmt.Errorf("WireGuard System-Tray-Symbol erschien nicht nach %d Sekunden", uiTimeoutSeconds)
				case <-ticker.C:
					if ui.RaiseUI() {
						return nil
					}
				}
			}
		},
		"/uninstallmanagerservice": func() error {
			if len(os.Args) != 2 {
				usage()
			}
			return manager.UninstallManager()
		},
		"/managerservice": func() error {
			if len(os.Args) != 2 {
				usage()
			}
			return manager.Run()
		},
		"/installtunnelservice": func() error {
			if len(os.Args) != 3 {
				usage()
			}
			return manager.InstallTunnel(os.Args[2])
		},
		"/uninstalltunnelservice": func() error {
			if len(os.Args) != 3 {
				usage()
			}
			return manager.UninstallTunnel(os.Args[2])
		},
		"/tunnelservice": func() error {
			if len(os.Args) != 3 {
				usage()
			}
			return tunnel.Run(os.Args[2])
		},
		"/ui": func() error {
			if len(os.Args) != 6 {
				usage()
			}
			var processToken windows.Token
			isAdmin := false
			if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken); err == nil {
				isAdmin = elevate.TokenIsElevatedOrElevatable(processToken)
				processToken.Close()
			}
			if isAdmin {
				if err := elevate.DropAllPrivileges(false); err != nil {
					return fmt.Errorf("Fehler beim Entfernen der Berechtigungen: %w", err)
				}
			}
			
			// Create pipes with proper cleanup
			pipes := make([]*os.File, 0, 3)
			defer func() {
				for _, pipe := range pipes {
					if pipe != nil {
						pipe.Close()
					}
				}
			}()
			
			readPipe, err := pipeFromHandleArgument(os.Args[2])
			if err != nil {
				return fmt.Errorf("Fehler beim Erstellen der Lesepipe: %w", err)
			}
			pipes = append(pipes, readPipe)
			
			writePipe, err := pipeFromHandleArgument(os.Args[3])
			if err != nil {
				return fmt.Errorf("Fehler beim Erstellen der Schreibpipe: %w", err)
			}
			pipes = append(pipes, writePipe)
			
			eventPipe, err := pipeFromHandleArgument(os.Args[4])
			if err != nil {
				return fmt.Errorf("Fehler beim Erstellen der Eventpipe: %w", err)
			}
			pipes = append(pipes, eventPipe)
			
			ringlogger.Global, err = ringlogger.NewRingloggerFromInheritedMappingHandle(os.Args[5], "GUI")
			if err != nil {
				return fmt.Errorf("Fehler beim Erstellen des Ringloggers: %w", err)
			}
			
			manager.InitializeIPCClient(readPipe, writePipe, eventPipe)
			ui.IsAdmin = isAdmin
			ui.RunUI()
			return nil
		},
		"/dumplog": func() error {
			if len(os.Args) != 2 && len(os.Args) != 3 {
				usage()
			}
			outputHandle, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
			if err != nil {
				return fmt.Errorf("Fehler beim Abrufen des stdout-Handles: %w", err)
			}
			if outputHandle == 0 {
				return fmt.Errorf("stdout muss gesetzt sein")
			}
			file := os.NewFile(uintptr(outputHandle), "stdout")
			defer file.Close()
			
			logPath, err := conf.LogFile(false)
			if err != nil {
				return fmt.Errorf("Fehler beim Abrufen des Log-Dateipfads: %w", err)
			}
			return ringlogger.DumpTo(logPath, file, len(os.Args) == 3 && os.Args[2] == "/tail")
		},
		"/update": func() error {
			if len(os.Args) != 2 {
				usage()
			}
			for progress := range updater.DownloadVerifyAndExecute(0) {
				if len(progress.Activity) > 0 {
					if progress.BytesTotal > 0 || progress.BytesDownloaded > 0 {
						var percent float64
						if progress.BytesTotal > 0 {
							percent = float64(progress.BytesDownloaded) / float64(progress.BytesTotal) * 100.0
						}
						log.Printf("%s: %d/%d (%.2f%%)\n", progress.Activity, progress.BytesDownloaded, progress.BytesTotal, percent)
					} else {
						log.Println(progress.Activity)
					}
				}
				if progress.Error != nil {
					log.Printf("Fehler: %v\n", progress.Error)
				}
				if progress.Complete || progress.Error != nil {
					return progress.Error
				}
			}
			return nil
		},
		"/removedriver": func() error {
			if len(os.Args) != 2 {
				usage()
			}
			_ = driver.UninstallLegacyWintun() // Best effort
			return driver.Uninstall()
		},
	}

	if handler, ok := commandHandlers[os.Args[1]]; ok {
		if err := handler(); err != nil {
			fatal(err)
		}
		return
	}

	usage()
}
