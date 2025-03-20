/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

 package tunnel

 import (
	 "log"
	 "sync"
	 "time"
 
	 "golang.org/x/sys/windows"
	 "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
 )
 
 // findDefaultLUID sucht nach dem Standard-Interface anhand der niedrigsten Metrik.
 // Es werden nur Routen mit einer Prefixlänge von 0 berücksichtigt, die nicht zu ourLUID gehören.
 func findDefaultLUID(family winipcfg.AddressFamily, ourLUID winipcfg.LUID, lastLUID *winipcfg.LUID, lastIndex *uint32) error {
	 routes, err := winipcfg.GetIPForwardTable2(family)
	 if err != nil {
		 return err
	 }
 
	 lowestMetric := ^uint32(0)
	 var chosenIndex uint32
	 var chosenLUID winipcfg.LUID
 
	 // Vorfilterung: Nur Default-Routen (PrefixLength 0) berücksichtigen, die nicht vom eigenen Interface stammen.
	 eligibleRoutes := make([]winipcfg.MibIPforwardRow2, 0, len(routes))
	 for i := range routes {
		 if routes[i].DestinationPrefix.PrefixLength == 0 && routes[i].InterfaceLUID != ourLUID {
			 eligibleRoutes = append(eligibleRoutes, routes[i])
		 }
	 }
 
	 // Auswahl der Route mit der niedrigsten Metrik
	 for i := range eligibleRoutes {
		 ifrow, err := eligibleRoutes[i].InterfaceLUID.Interface()
		 if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			 continue
		 }
 
		 iface, err := eligibleRoutes[i].InterfaceLUID.IPInterface(family)
		 if err != nil {
			 continue
		 }
 
		 metric := eligibleRoutes[i].Metric + iface.Metric
		 if metric < lowestMetric {
			 lowestMetric = metric
			 chosenIndex = eligibleRoutes[i].InterfaceIndex
			 chosenLUID = eligibleRoutes[i].InterfaceLUID
		 }
	 }
 
	 // Aktualisieren, falls sich der Standard geändert hat.
	 if chosenLUID == *lastLUID && chosenIndex == *lastIndex {
		 return nil
	 }
 
	 *lastLUID = chosenLUID
	 *lastIndex = chosenIndex
	 return nil
 }
 
 type mtuState struct {
	 mutex      sync.Mutex
	 lastLUID   winipcfg.LUID
	 lastIndex  uint32
	 lastMTU    uint32
	 lastUpdate time.Time
	 minMTU     uint32
 }
 
 // monitorMTU überwacht Änderungen der MTU und passt das Tunnel-Interface entsprechend an.
 // Es registriert Callback-Funktionen, die bei Änderungen der Routingtabelle oder Interface-Parameter aufgerufen werden.
 func monitorMTU(family winipcfg.AddressFamily, ourLUID winipcfg.LUID) ([]winipcfg.ChangeCallback, error) {
	 state := &mtuState{
		 lastIndex: ^uint32(0),
	 }
 
	 // Mindest-MTU basierend auf dem IP-Familientyp setzen
	 if family == windows.AF_INET {
		 state.minMTU = 576
	 } else if family == windows.AF_INET6 {
		 state.minMTU = 1280
	 }
 
	 // updateMTU führt die Aktualisierung der MTU durch, wenn nötig.
	 updateMTU := func() error {
		 state.mutex.Lock()
		 defer state.mutex.Unlock()
 
		 // Throttling: Updates maximal alle 250ms durchführen
		 now := time.Now()
		 if now.Sub(state.lastUpdate) < 250*time.Millisecond {
			 return nil
		 }
		 state.lastUpdate = now
 
		 if err := findDefaultLUID(family, ourLUID, &state.lastLUID, &state.lastIndex); err != nil {
			 return err
		 }
 
		 var mtu uint32 = 0
		 if state.lastLUID != 0 {
			 iface, err := state.lastLUID.Interface()
			 if err != nil {
				 return err
			 }
			 if iface.MTU > 0 {
				 mtu = iface.MTU
			 }
		 }
 
		 // Nur wenn sich die MTU des Standard-Interfaces geändert hat, wird der Tunnel angepasst.
		 if mtu > 0 && state.lastMTU != mtu {
			 iface, err := ourLUID.IPInterface(family)
			 if err != nil {
				 return err
			 }
 
			 newMTU := mtu - 80
			 if newMTU < state.minMTU {
				 newMTU = state.minMTU
			 }
 
			 // Änderung vornehmen, wenn der neue MTU-Wert sich unterscheidet.
			 if iface.NLMTU != newMTU {
				 iface.NLMTU = newMTU
				 if err := iface.Set(); err != nil {
					 return err
				 }
			 }
 
			 state.lastMTU = mtu
		 }
		 return nil
	 }
 
	 // Initiale Aktualisierung
	 if err := updateMTU(); err != nil {
		 return nil, err
	 }
 
	 // Registrieren des Callback für Routenänderungen
	 routeCallback, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		 // Nur auf Default-Routen reagieren
		 if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			 if err := updateMTU(); err != nil {
				 log.Printf("Error in route callback: %v", err)
			 }
		 }
	 })
	 if err != nil {
		 return nil, err
	 }
 
	 // Registrieren des Callback für Interface-Änderungen
	 ifaceCallback, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		 if notificationType == winipcfg.MibParameterNotification {
			 if err := updateMTU(); err != nil {
				 log.Printf("Error in interface callback: %v", err)
			 }
		 }
	 })
	 if err != nil {
		 routeCallback.Unregister()
		 return nil, err
	 }
 
	 return []winipcfg.ChangeCallback{routeCallback, ifaceCallback}, nil
 }
 