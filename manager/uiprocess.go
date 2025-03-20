/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

 package manager

 import (
	 "errors"
	 "runtime"
	 "sync/atomic"
	 "syscall"
	 "unsafe"
 
	 "golang.org/x/sys/windows"
 )
 
 // uiProcess repräsentiert einen laufenden UI-Prozess mit seinem Handle.
 type uiProcess struct {
	 handle uintptr
 }
 
 // launchUIProcess startet einen neuen UI-Prozess unter Windows mit den angegebenen Parametern.
 func launchUIProcess(executable string, args []string, workingDirectory string, handles []windows.Handle, token windows.Token) (*uiProcess, error) {
	 // Konvertiere Strings in UTF16-Zeiger mit Fehlerbehandlung
	 executable16, err := windows.UTF16PtrFromString(executable)
	 if err != nil {
		 return nil, err
	 }
	 args16, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	 if err != nil {
		 return nil, err
	 }
	 workingDirectory16, err := windows.UTF16PtrFromString(workingDirectory)
	 if err != nil {
		 return nil, err
	 }
 
	 // Erstelle Environment-Block mit Fehlerbehandlung
	 var environmentBlock *uint16
	 if err := windows.CreateEnvironmentBlock(&environmentBlock, token, false); err != nil {
		 return nil, err
	 }
	 defer windows.DestroyEnvironmentBlock(environmentBlock)
 
	 // Erstelle und verwalte Prozessattributliste
	 attributeList, err := windows.NewProcThreadAttributeList(1)
	 if err != nil {
		 return nil, err
	 }
	 defer attributeList.Delete()
 
	 // Initialisiere StartupInfo mit korrekter Größe
	 si := &windows.StartupInfoEx{
		 StartupInfo:             windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))},
		 ProcThreadAttributeList: attributeList.List(),
	 }
 
	 // Aktualisiere Attributliste mit Handles nur, wenn welche vorhanden sind
	 var handlePtr unsafe.Pointer
	 if len(handles) > 0 {
		 handlePtr = unsafe.Pointer(&handles[0])
	 } else {
		 handlePtr = unsafe.Pointer(uintptr(0)) // Nullzeiger für leere Liste
	 }
	 attributeList.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handlePtr, uintptr(len(handles))*unsafe.Sizeof(windows.Handle(0)))
 
	 // Erstelle Prozess mit optimierten Flags; creationFlags als uint32 deklariert
	 var creationFlags uint32 = windows.CREATE_DEFAULT_ERROR_MODE | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT
 
	 pi := new(windows.ProcessInformation)
	 err = windows.CreateProcessAsUser(
		 token,
		 executable16,
		 args16,
		 nil,
		 nil,
		 true,
		 creationFlags,
		 environmentBlock,
		 workingDirectory16,
		 &si.StartupInfo,
		 pi,
	 )
	 if err != nil {
		 return nil, err
	 }
 
	 // Schließe Thread-Handle sofort, da er nicht benötigt wird
	 windows.CloseHandle(pi.Thread)
 
	 // Erstelle und gebe uiProcess mit Finalizer zurück
	 uiProc := &uiProcess{handle: uintptr(pi.Process)}
	 runtime.SetFinalizer(uiProc, (*uiProcess).release)
	 return uiProc, nil
 }
 
 // release gibt den Prozess-Handle frei und setzt ihn auf ungültig.
 func (p *uiProcess) release() error {
	 handle := windows.Handle(atomic.SwapUintptr(&p.handle, uintptr(windows.InvalidHandle)))
	 if handle == windows.InvalidHandle {
		 return nil
	 }
	 if err := windows.CloseHandle(handle); err != nil {
		 return err
	 }
	 runtime.SetFinalizer(p, nil)
	 return nil
 }
 
 // Wait wartet auf das Ende des Prozesses und gibt den Exit-Code zurück.
 func (p *uiProcess) Wait() (uint32, error) {
	 handle := windows.Handle(atomic.LoadUintptr(&p.handle))
	 if handle == windows.InvalidHandle {
		 return 0, errors.New("process handle is closed")
	 }
 
	 s, err := windows.WaitForSingleObject(handle, syscall.INFINITE)
	 if err != nil {
		 return 0, err
	 }
 
	 switch s {
	 case windows.WAIT_OBJECT_0:
		 var exitCode uint32
		 if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
			 return 0, err
		 }
		 p.release()
		 return exitCode, nil
	 case windows.WAIT_FAILED:
		 return 0, err
	 default:
		 return 0, errors.New("unexpected result from WaitForSingleObject")
	 }
 }
 
 // Kill beendet den Prozess mit einem Exit-Code von 1.
 func (p *uiProcess) Kill() error {
	 handle := windows.Handle(atomic.LoadUintptr(&p.handle))
	 if handle == windows.InvalidHandle {
		 return nil
	 }
	 return windows.TerminateProcess(handle, 1)
 }
 