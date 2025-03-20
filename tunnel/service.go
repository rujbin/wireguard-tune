/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
	"math"
	"sync"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type tunnelService struct {
	Path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	var watcher *interfaceWatcher
	var adapter *driver.Adapter
	var luid winipcfg.LUID
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create wait group for cleanup operations
	var cleanupWg sync.WaitGroup

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		serviceState = svc.StopPending
		changes <- svc.Status{State: serviceState}

		// Setup shutdown timeout using context
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		// Create channel for shutdown completion
		shutdownDone := make(chan struct{})
		go func() {
			defer close(shutdownDone)
			cleanupWg.Wait()
		}()

		// Wait for cleanup or timeout
		select {
		case <-shutdownDone:
			log.Println("Cleanup completed successfully")
		case <-shutdownCtx.Done():
			// Dump stack trace on timeout
			buf := make([]byte, 1024)
			for {
				n := runtime.Stack(buf, true)
				if n < len(buf) {
					buf = buf[:n]
					break
				}
				buf = make([]byte, 2*len(buf))
			}
			lines := bytes.Split(buf, []byte{'\n'})
			log.Println("Failed to shutdown after 30 seconds. Probably deadlocked. Printing stack and killing.")
			for _, line := range lines {
				if len(bytes.TrimSpace(line)) > 0 {
					log.Println(string(line))
				}
			}
			os.Exit(777)
		}

		if logErr == nil && adapter != nil && config != nil {
			cleanupWg.Add(1)
			go func() {
				defer cleanupWg.Done()
				if err := runScriptCommand(config.Interface.PreDown, config.Name); err != nil {
					log.Printf("Warning: PreDown script failed: %v", err)
				}
			}()
		}

		if watcher != nil {
			cleanupWg.Add(1)
			go func() {
				defer cleanupWg.Done()
				watcher.Destroy()
			}()
		}

		if adapter != nil {
			cleanupWg.Add(1)
			go func() {
				defer cleanupWg.Done()
				adapter.Close()
			}()
		}

		if logErr == nil && adapter != nil && config != nil {
			cleanupWg.Add(1)
			go func() {
				defer cleanupWg.Done()
				if err := runScriptCommand(config.Interface.PostDown, config.Name); err != nil {
					log.Printf("Warning: PostDown script failed: %v", err)
				}
			}()
		}

		log.Println("Shutting down")
	}()

	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	services.PrintStarting()

	if services.StartedAtBoot() {
		if m, err := mgr.Connect(); err == nil {
			if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
				log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState}
			}
			m.Disconnect()
		}
	}

	evaluateStaticPitfalls()

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating network adapter")
	for i := 0; i < 15; i++ {
		if i > 0 {
			sleepSeconds := math.Pow(2, float64(i))
			if sleepSeconds > 30 {
				sleepSeconds = 30
			}
			sleepTime := time.Duration(sleepSeconds) * time.Second
			time.Sleep(sleepTime)
			log.Printf("Retrying adapter creation (attempt %d, waited %v): %v", i+1, sleepTime, err)
		}
		adapter, err = driver.CreateAdapter(config.Name, "WireGuard", deterministicGUID(config))
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("Error creating adapter: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}
	luid = adapter.LUID()
	driverVersion, err := driver.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine driver version: %v", err)
	} else {
		log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
	}
	err = adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		err = fmt.Errorf("Error enabling adapter logging: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	err = enableFirewall(config, luid)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	log.Println("Setting interface configuration")
	err = adapter.SetConfiguration(config.ToDriverConfiguration())
	if err != nil {
		err = fmt.Errorf("failed to set adapter configuration: %w", err)
		serviceError = services.ErrorDeviceSetConfig
		return
	}

	log.Println("Bringing adapter up")
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		err = fmt.Errorf("failed to bring adapter up: %w", err)
		serviceError = services.ErrorDeviceBringUp
		return
	}
	watcher.Configure(adapter, config, luid)

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	var started bool
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				cancel() // Cancel context to initiate graceful shutdown
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-watcher.started:
			if !started {
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				log.Println("Startup complete")
				started = true
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		case <-ctx.Done():
			return
		}
	}
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := conf.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}
