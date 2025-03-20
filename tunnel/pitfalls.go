/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

 package tunnel

 import (
	 "log"
	 "net/netip"
	 "strings"
	 "sync"
	 "time"
	 "unsafe"
 
	 "golang.org/x/sys/windows"
	 "golang.org/x/sys/windows/svc/mgr"
	 "golang.zx2c4.com/wireguard/windows/conf"
	 "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
 )
 
 var (
	 dnsCacheCheckOnce sync.Once
	 dnsCacheDisabled  bool
	 dnsCacheTime      time.Time
	 dnsCacheDuration  = 5 * time.Minute
 )
 
 func evaluateStaticPitfalls() {
	 go func() {
		 pitfallDnsCacheDisabled()
		 pitfallVirtioNetworkDriver()
	 }()
 }
 
 func evaluateDynamicPitfalls(family winipcfg.AddressFamily, conf *conf.Config, luid winipcfg.LUID) {
	 go func() {
		 pitfallWeakHostSend(family, conf, luid)
	 }()
 }
 
 func pitfallDnsCacheDisabled() {
	 dnsCacheCheckOnce.Do(func() {
		 scm, err := mgr.Connect()
		 if err != nil {
			 return
		 }
		 defer scm.Disconnect()
		 svc := mgr.Service{Name: "dnscache"}
		 svc.Handle, err = windows.OpenService(scm.Handle, windows.StringToUTF16Ptr(svc.Name), windows.SERVICE_QUERY_CONFIG)
		 if err != nil {
			 return
		 }
		 defer svc.Close()
		 cfg, err := svc.Config()
		 if err != nil {
			 return
		 }
		 dnsCacheDisabled = cfg.StartType == mgr.StartDisabled
		 dnsCacheTime = time.Now()
	 })
 
	 if time.Since(dnsCacheTime) > dnsCacheDuration {
		 // Reset Once, damit die Prüfung nach Ablauf der Dauer erneut ausgeführt wird.
		 dnsCacheCheckOnce = sync.Once{}
		 pitfallDnsCacheDisabled()
		 return
	 }
 
	 if dnsCacheDisabled {
		 log.Printf("Warning: the %q (dnscache) service is disabled; please re-enable it", "DNS Client")
	 }
 }
 
 func pitfallVirtioNetworkDriver() {
	 var modules []windows.RTL_PROCESS_MODULE_INFORMATION
	 bufferSize := uint32(128 * 1024)
	 moduleBuffer := make([]byte, bufferSize)
	 err := windows.NtQuerySystemInformation(windows.SystemModuleInformation, unsafe.Pointer(&moduleBuffer[0]), bufferSize, &bufferSize)
	 if err != nil {
		 return
	 }
	 mods := (*windows.RTL_PROCESS_MODULES)(unsafe.Pointer(&moduleBuffer[0]))
	 modules = unsafe.Slice(&mods.Modules[0], mods.NumberOfModules)
 
	 for i := range modules {
		 moduleName := windows.ByteSliceToString(modules[i].FullPathName[modules[i].OffsetToFileName:])
		 if !strings.EqualFold(moduleName, "netkvm.sys") {
			 continue
		 }
		 driverPath := `\\?\GLOBALROOT` + windows.ByteSliceToString(modules[i].FullPathName[:])
		 var zero windows.Handle
		 infoSize, err := windows.GetFileVersionInfoSize(driverPath, &zero)
		 if err != nil {
			 return
		 }
		 versionInfo := make([]byte, infoSize)
		 err = windows.GetFileVersionInfo(driverPath, 0, infoSize, unsafe.Pointer(&versionInfo[0]))
		 if err != nil {
			 return
		 }
		 // Fehlerbehebung: Verwende eine lokale Variable statt eines nicht initialisierten Zeigers.
		 var fixedInfo windows.VS_FIXEDFILEINFO
		 fixedInfoLen := uint32(unsafe.Sizeof(fixedInfo))
		 err = windows.VerQueryValue(unsafe.Pointer(&versionInfo[0]), `\`, unsafe.Pointer(&fixedInfo), &fixedInfoLen)
		 if err != nil {
			 return
		 }
		 version := (uint64(fixedInfo.FileVersionMS) << 32) | uint64(fixedInfo.FileVersionLS)
		 // Es wird nun gewarnt, wenn die Version im problematischen Bereich liegt.
		 if version >= 0x6400556800005140 || version < 0x2800000000000000 {
			 return
		 }
		 log.Println("Warning: the VirtIO network driver (NetKVM) is out of date and may cause known problems; please update to v100.85.104.20800 or later")
		 return
	 }
 }
 
 func pitfallWeakHostSend(family winipcfg.AddressFamily, conf *conf.Config, ourLUID winipcfg.LUID) {
	 routingTable, err := winipcfg.GetIPForwardTable2(family)
	 if err != nil {
		 return
	 }
 
	 type endpointRoute struct {
		 addr         netip.Addr
		 name         string
		 lowestMetric uint32
		 highestCIDR  uint8
		 weakHostSend bool
		 finalIsOurs  bool
	 }
 
	 endpoints := make([]endpointRoute, 0, len(conf.Peers))
	 for _, peer := range conf.Peers {
		 addr, err := netip.ParseAddr(peer.Endpoint.Host)
		 if err != nil || (addr.Is4() && family != windows.AF_INET) || (addr.Is6() && family != windows.AF_INET6) {
			 continue
		 }
		 endpoints = append(endpoints, endpointRoute{addr: addr, lowestMetric: ^uint32(0)})
	 }
 
	 // Cache interface information to reduce API calls
	 interfaceCache := make(map[winipcfg.LUID]*winipcfg.MibIfRow2)
	 ipInterfaceCache := make(map[winipcfg.LUID]*winipcfg.MibIPInterfaceRow)
 
	 for i := range routingTable {
		 for j := range endpoints {
			 r, e := &routingTable[i], &endpoints[j]
			 if r.DestinationPrefix.PrefixLength < e.highestCIDR {
				 continue
			 }
			 if !r.DestinationPrefix.Prefix().Contains(e.addr) {
				 continue
			 }
 
			 ifrow, exists := interfaceCache[r.InterfaceLUID]
			 if !exists {
				 var err error
				 ifrow, err = r.InterfaceLUID.Interface()
				 if err != nil {
					 continue
				 }
				 interfaceCache[r.InterfaceLUID] = ifrow
			 }
 
			 if ifrow.OperStatus != winipcfg.IfOperStatusUp {
				 continue
			 }
 
			 ifacerow, exists := ipInterfaceCache[r.InterfaceLUID]
			 if !exists {
				 var err error
				 ifacerow, err = r.InterfaceLUID.IPInterface(family)
				 if err != nil {
					 continue
				 }
				 ipInterfaceCache[r.InterfaceLUID] = ifacerow
			 }
 
			 metric := r.Metric + ifacerow.Metric
			 if r.DestinationPrefix.PrefixLength == e.highestCIDR && metric > e.lowestMetric {
				 continue
			 }
 
			 e.lowestMetric = metric
			 e.highestCIDR = r.DestinationPrefix.PrefixLength
			 e.finalIsOurs = r.InterfaceLUID == ourLUID
			 // Setze die Felder immer, damit auch für unsere Routen der Wert ermittelt wird.
			 e.name = ifrow.Alias()
			 e.weakHostSend = ifacerow.ForwardingEnabled || ifacerow.WeakHostSend
		 }
	 }
 
	 problematicInterfaces := make(map[string]bool, len(endpoints))
	 // Warnung ausgeben, wenn der beste Routenpfad NICHT zu unserem Interface gehört und die betreffende Schnittstelle Forwarding/WeakHostSend aktiviert hat.
	 for _, e := range endpoints {
		 if e.weakHostSend && !e.finalIsOurs {
			 problematicInterfaces[e.name] = true
		 }
	 }
 
	 for iface := range problematicInterfaces {
		 log.Printf("Warning: the %q interface has Forwarding/WeakHostSend enabled, which will cause routing loops", iface)
	 }
 }
 