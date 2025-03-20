/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"

	"github.com/lxn/walk"
)

// Global start time for UpdateFound timing
//var startTime = time.Now()

// Status + active CIDRs + separator
const trayTunnelActionsOffset = 3

type Tray struct {
	*walk.NotifyIcon

	// Current known tunnels by name
	tunnels                  map[string]*walk.Action
	tunnelsAreInBreakoutMenu bool

	mtw *ManageTunnelsWindow

	tunnelChangedCB  *manager.TunnelChangeCallback
	tunnelsChangedCB *manager.TunnelsChangeCallback

	clicked func()
}

func NewTray(mtw *ManageTunnelsWindow) (*Tray, error) {
	var err error

	tray := &Tray{
		mtw:     mtw,
		tunnels: make(map[string]*walk.Action),
	}

	tray.NotifyIcon, err = walk.NewNotifyIcon(mtw)
	if err != nil {
		return nil, err
	}

	return tray, tray.setup()
}

func (tray *Tray) setup() error {
	tray.clicked = tray.onManageTunnels

	tray.SetToolTip(l18n.Sprintf("WireGuard: Deactivated"))
	tray.SetVisible(true)
	if icon, err := loadLogoIcon(16); err == nil {
		tray.SetIcon(icon)
	}

	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			tray.clicked()
		}
	})
	tray.MessageClicked().Attach(func() {
		tray.clicked()
	})

	for _, item := range [...]struct {
		label     string
		handler   walk.EventHandler
		enabled   bool
		hidden    bool
		separator bool
		defawlt   bool // "defawlt" wird bewusst gewählt, da "default" ein Keyword ist.
	}{
		{label: l18n.Sprintf("Status: Unknown")},
		{label: l18n.Sprintf("Addresses: None"), hidden: true},
		{separator: true},
		{separator: true},
		{label: l18n.Sprintf("&Manage tunnels…"), handler: tray.onManageTunnels, enabled: true, defawlt: true},
		{label: l18n.Sprintf("&Import tunnel(s) from file…"), handler: tray.onImport, enabled: true, hidden: !IsAdmin},
		{separator: true},
		{label: l18n.Sprintf("&About WireGuard…"), handler: tray.onAbout, enabled: true},
		{label: l18n.Sprintf("E&xit"), handler: onQuit, enabled: true, hidden: !IsAdmin},
	} {
		var action *walk.Action
		if item.separator {
			action = walk.NewSeparatorAction()
		} else {
			action = walk.NewAction()
			action.SetText(item.label)
			action.SetEnabled(item.enabled)
			action.SetVisible(!item.hidden)
			action.SetDefault(item.defawlt)
			if item.handler != nil {
				action.Triggered().Attach(item.handler)
			}
		}

		tray.ContextMenu().Actions().Add(action)
	}
	tray.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(tray.onTunnelChange)
	tray.tunnelsChangedCB = manager.IPCClientRegisterTunnelsChange(tray.onTunnelsChange)
	tray.onTunnelsChange()
	globalState, _ := manager.IPCClientGlobalState()
	tray.updateGlobalState(globalState)

	return nil
}

func (tray *Tray) Dispose() error {
	if tray.tunnelChangedCB != nil {
		tray.tunnelChangedCB.Unregister()
		tray.tunnelChangedCB = nil
	}
	if tray.tunnelsChangedCB != nil {
		tray.tunnelsChangedCB.Unregister()
		tray.tunnelsChangedCB = nil
	}
	return tray.NotifyIcon.Dispose()
}

func (tray *Tray) onTunnelsChange() {
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return
	}
	tray.mtw.Synchronize(func() {
		tunnelSet := make(map[string]bool, len(tunnels))
		for _, tunnel := range tunnels {
			tunnelSet[tunnel.Name] = true
			if tray.tunnels[tunnel.Name] == nil {
				tray.addTunnelAction(&tunnel)
			}
		}
		for trayTunnel := range tray.tunnels {
			if !tunnelSet[trayTunnel] {
				tray.removeTunnelAction(trayTunnel)
			}
		}
	})
}

func (tray *Tray) sortedTunnels() []string {
	names := make([]string, 0, len(tray.tunnels))
	for name := range tray.tunnels {
		names = append(names, name)
	}
	sort.SliceStable(names, func(i, j int) bool {
		return conf.TunnelNameIsLess(names[i], names[j])
	})
	return names
}

func (tray *Tray) addTunnelAction(tunnel *manager.Tunnel) {
	tunnelAction := walk.NewAction()
	tunnelAction.SetText(tunnel.Name)
	tunnelAction.SetEnabled(true)
	tunnelAction.SetCheckable(true)
	tunnelAction.Triggered().Attach(func() {
		tunnelAction.SetChecked(!tunnelAction.Checked())
		 // Nutze einen parameterisierten Goroutine-Aufruf, um den State abzufragen:
		go func(t *manager.Tunnel) {
			state, err := t.State()
			if err != nil {
				return
			}
			tray.mtw.Synchronize(func() {
				tray.setTunnelState(t, state)
			})
		}(tunnel)
	})
	tray.tunnels[tunnel.Name] = tunnelAction

	var (
		idx  int
		name string
	)
	for idx, name = range tray.sortedTunnels() {
		if name == tunnel.Name {
			break
		}
	}

	if tray.tunnelsAreInBreakoutMenu {
		if tray.ContextMenu().Actions().Len() > trayTunnelActionsOffset {
			tray.ContextMenu().Actions().At(trayTunnelActionsOffset).Menu().Actions().Insert(idx, tunnelAction)
		}
	} else {
		tray.ContextMenu().Actions().Insert(trayTunnelActionsOffset+idx, tunnelAction)
	}
	tray.rebalanceTunnelsMenu()

	go func() {
		state, err := tunnel.State()
		if err != nil {
			return
		}
		tray.mtw.Synchronize(func() {
			tray.setTunnelState(tunnel, state)
		})
	}()
}

func (tray *Tray) removeTunnelAction(tunnelName string) {
	if tray.tunnelsAreInBreakoutMenu {
		if tray.ContextMenu().Actions().Len() > trayTunnelActionsOffset {
			tray.ContextMenu().Actions().At(trayTunnelActionsOffset).Menu().Actions().Remove(tray.tunnels[tunnelName])
		}
	} else {
		tray.ContextMenu().Actions().Remove(tray.tunnels[tunnelName])
	}
	delete(tray.tunnels, tunnelName)
	tray.rebalanceTunnelsMenu()
}

func (tray *Tray) rebalanceTunnelsMenu() {
	actions := tray.ContextMenu().Actions()
	if tray.tunnelsAreInBreakoutMenu && len(tray.tunnels) <= 10 {
		if actions.Len() > trayTunnelActionsOffset {
			menuAction := actions.At(trayTunnelActionsOffset)
			idx := 1
			for _, name := range tray.sortedTunnels() {
				actions.Insert(trayTunnelActionsOffset+idx, tray.tunnels[name])
				idx++
			}
			actions.Remove(menuAction)
			if menuAction.Menu() != nil { // Schütze vor nil-Panik
				menuAction.Menu().Dispose()
			}
			tray.tunnelsAreInBreakoutMenu = false
		}
	} else if !tray.tunnelsAreInBreakoutMenu && len(tray.tunnels) > 10 {
		menu, err := walk.NewMenu()
		if err != nil {
			return
		}
		for _, name := range tray.sortedTunnels() {
			action := tray.tunnels[name]
			menu.Actions().Add(action)
			actions.Remove(action)
		}
		menuAction, err := actions.InsertMenu(trayTunnelActionsOffset, menu)
		if err != nil {
			return
		}
		menuAction.SetText(l18n.Sprintf("&Tunnels"))
		tray.tunnelsAreInBreakoutMenu = true
	}
}

func (tray *Tray) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	tray.mtw.Synchronize(func() {
		tray.updateGlobalState(globalState)
		if err == nil {
			tunnelAction := tray.tunnels[tunnel.Name]
			if tunnelAction != nil {
				wasChecked := tunnelAction.Checked()
				switch state {
				case manager.TunnelStarted:
					if !wasChecked {
						if icon, err := iconWithOverlayForState(state, 128); err == nil {
							tray.ShowCustom(l18n.Sprintf("WireGuard Activated"), l18n.Sprintf("The %s tunnel has been activated.", tunnel.Name), icon)
						}
					}

				case manager.TunnelStopped:
					if wasChecked {
						if icon, err := loadSystemIcon("imageres", -31, 128); err == nil { // TODO: this icon isn't sehr gut...
							tray.ShowCustom(l18n.Sprintf("WireGuard Deactivated"), l18n.Sprintf("The %s tunnel has been deactivated.", tunnel.Name), icon)
						}
					}
				}
			}
		} else if !tray.mtw.Visible() {
			tray.ShowError(l18n.Sprintf("WireGuard Tunnel Error"), err.Error())
		}
		tray.setTunnelState(tunnel, state)
	})
}

func (tray *Tray) updateGlobalState(globalState manager.TunnelState) {
	// Setze neues Icon, falls möglich.
	if icon, err := iconWithOverlayForState(globalState, 16); err == nil {
		tray.SetIcon(icon)
	}
	actions := tray.ContextMenu().Actions()
	// Absicherung: Es sollten mindestens zwei Actions vorhanden sein.
	if actions.Len() < 2 {
		return
	}
	statusAction := actions.At(0)

	tray.SetToolTip(l18n.Sprintf("WireGuard: %s", textForState(globalState, true)))
	stateText := textForState(globalState, false)
	if stateIcon, err := iconForState(globalState, 16); err == nil {
		statusAction.SetImage(stateIcon)
	}
	statusAction.SetText(l18n.Sprintf("Status: %s", stateText))

	go func() {
		var addrs []string
		if tunnels, err := manager.IPCClientTunnels(); err == nil {
			addrs = make([]string, 0, len(tunnels)*2)
			for i := range tunnels {
				if state, err := tunnels[i].State(); err == nil && state == manager.TunnelStarted {
					if config, err := tunnels[i].RuntimeConfig(); err == nil {
						for _, addr := range config.Interface.Addresses {
							addrs = append(addrs, addr.String())
						}
					}
				}
			}
		}
		tray.mtw.Synchronize(func() {
			actions := tray.ContextMenu().Actions()
			if actions.Len() < 2 {
				return
			}
			activeCIDRsAction := actions.At(1)
			activeCIDRsAction.SetText(l18n.Sprintf("Addresses: %s", strings.Join(addrs, l18n.EnumerationSeparator())))
			activeCIDRsAction.SetVisible(len(addrs) > 0)
		})
	}()

	for _, action := range tray.tunnels {
		action.SetEnabled(globalState == manager.TunnelStarted || globalState == manager.TunnelStopped)
	}
}

func (tray *Tray) setTunnelState(tunnel *manager.Tunnel, state manager.TunnelState) {
	tunnelAction := tray.tunnels[tunnel.Name]
	if tunnelAction == nil {
		return
	}

	switch state {
	case manager.TunnelStarted:
		tunnelAction.SetEnabled(true)
		tunnelAction.SetChecked(true)
	case manager.TunnelStopped:
		tunnelAction.SetChecked(false)
	}
}

func (tray *Tray) UpdateFound() {
	action := walk.NewAction()
	action.SetText(l18n.Sprintf("An Update is Available!"))
	if menuIcon, err := loadShieldIcon(16); err == nil {
		action.SetImage(menuIcon)
	}
	action.SetDefault(true)
	showUpdateTab := func() {
		if !tray.mtw.Visible() {
			tray.mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
		}
		tray.mtw.tabs.SetCurrentIndex(2)
		raise(tray.mtw.Handle())
	}
	action.Triggered().Attach(showUpdateTab)
	tray.clicked = showUpdateTab
	actions := tray.ContextMenu().Actions()
	if actions.Len() >= 2 {
		actions.Insert(actions.Len()-2, action)
	}

	showUpdateBalloon := func() {
		if icon, err := loadShieldIcon(128); err == nil {
			tray.ShowCustom(l18n.Sprintf("WireGuard Update Available"), l18n.Sprintf("An update to WireGuard is now available. You are advised to update as soon as possible."), icon)
		}
	}

	delta := time.Since(startTime)
	if delta < 3*time.Second {
		time.AfterFunc(3*time.Second-delta, func() {
			tray.mtw.Synchronize(showUpdateBalloon)
		})
	} else {
		showUpdateBalloon()
	}
}

func (tray *Tray) onManageTunnels() {
	tray.mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
	tray.mtw.tabs.SetCurrentIndex(0)
	raise(tray.mtw.Handle())
}

func (tray *Tray) onAbout() {
	if tray.mtw.Visible() {
		onAbout(tray.mtw)
	} else {
		onAbout(nil)
	}
}

func (tray *Tray) onImport() {
	raise(tray.mtw.Handle())
	tray.mtw.tunnelsPage.onImport()
}
