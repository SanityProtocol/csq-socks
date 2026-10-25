/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * csq-socks: the kill switch of csq-socks tun, adapted from wireguard-windows v0.5.3 tunnel/firewall/blocker.go.
 * The session is not dynamic: the filters stay after this process exits — however it exits — until Disable or a
 * reboot, like the unreachable route of tun on Linux. Each filter has a stable key (filterBase + its index), so
 * Disable needs nothing remembered and Enable first clears what an earlier run left.
 */

package firewall

import (
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var (
	providerKey = windows.GUID{Data1: 0x5c0a7e21, Data2: 0x3c41, Data3: 0x4d6a, Data4: [8]byte{0x9b, 0x1e, 0x6a, 0x51, 0x0c, 0x5f, 0x7a, 0x01}}
	sublayerKey = windows.GUID{Data1: 0x5c0a7e21, Data2: 0x3c41, Data3: 0x4d6a, Data4: [8]byte{0x9b, 0x1e, 0x6a, 0x51, 0x0c, 0x5f, 0x7a, 0x02}}
	filterBase  = windows.GUID{Data1: 0x5c0a7e22, Data2: 0x3c41, Data3: 0x4d6a, Data4: [8]byte{0x9b, 0x1e, 0x6a, 0x51, 0x0c, 0x5f, 0x00, 0x00}}
)

const maxFilters = 64

var nextFilter int

func filterKey(i int) windows.GUID {
	k := filterBase
	k.Data4[6], k.Data4[7] = byte(i>>8), byte(i)
	return k
}

// fwpmFilterAdd0: every filter the rules add gets the next stable key
func fwpmFilterAdd0(engineHandle uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error {
	if nextFilter >= maxFilters {
		return errors.New("too many filters")
	}
	filter.filterKey = filterKey(nextFilter)
	nextFilter++
	return fwpmFilterAdd0Raw(engineHandle, filter, sd, id)
}

func openSession() (uintptr, error) {
	displayData, err := createWtFwpmDisplayData0("csq-socks", "csq-socks tun kill switch")
	if err != nil {
		return 0, wrapErr(err)
	}
	session := wtFwpmSession0{
		displayData:          *displayData,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	handle := uintptr(0)
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return 0, wrapErr(err)
	}
	return handle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{provider: providerKey, filters: sublayerKey}
	displayData, err := createWtFwpmDisplayData0("csq-socks", "csq-socks tun")
	if err != nil {
		return nil, wrapErr(err)
	}
	provider := wtFwpmProvider0{providerKey: bo.provider, displayData: *displayData}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, wrapErr(err)
	}
	displayData, err = createWtFwpmDisplayData0("csq-socks filters", "Permissive and blocking filters")
	if err != nil {
		return nil, wrapErr(err)
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *displayData,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if err := fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, wrapErr(err)
	}
	return bo, nil
}

// Enable blocks everything but the tunnel interface (luid), the program clientExe, loopback, DHCP, NDP and the LAN,
// replacing in one transaction what an earlier Enable left.
// dnsServers, when given, are the only DNS servers anything but clientExe may reach, LAN ones included.
func Enable(luid uint64, clientExe string, dnsServers []netip.Addr) error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	nextFilter = 0
	// what an earlier run left goes in the same transaction the new filters come in: never a moment without either
	return runTransaction(session, func(session uintptr) error {
		removeAll(session)
		bo, err := registerBaseObjects(session)
		if err != nil {
			return err
		}
		if err := permitApp(session, bo, 15, clientExe); err != nil {
			return err
		}
		if len(dnsServers) > 0 {
			if err := blockDNS(dnsServers, session, bo, 15, 14); err != nil {
				return err
			}
		}
		for _, f := range []func() error{
			func() error { return permitLoopback(session, bo, 13) },
			func() error { return permitTunInterface(session, bo, 12, luid) },
			func() error { return permitDHCPIPv4(session, bo, 12) },
			func() error { return permitDHCPIPv6(session, bo, 12) },
			func() error { return permitNdp(session, bo, 12) },
			func() error { return permitLAN(session, bo, 12) },
			func() error { return blockAll(session, bo, 0) },
		} {
			if err := f(); err != nil {
				return err
			}
		}
		return nil
	})
}

// Disable removes every filter Enable can have added, then the sublayer and the provider; nothing there is no error.
func Disable() error {
	session, err := openSession()
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	removeAll(session)
	return nil
}

func removeAll(session uintptr) {
	for i := 0; i < maxFilters; i++ {
		k := filterKey(i)
		fwpmDeleteByKey(procFwpmFilterDeleteByKey0, session, &k)
	}
	fwpmDeleteByKey(procFwpmSubLayerDeleteByKey0, session, &sublayerKey)
	fwpmDeleteByKey(procFwpmProviderDeleteByKey0, session, &providerKey)
}
