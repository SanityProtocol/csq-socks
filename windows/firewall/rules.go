/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * csq-socks: adapted from wireguard-windows v0.5.3 tunnel/firewall (permitApp, permitLAN; the service rule and
 * Hyper-V rule dropped).
 */

package firewall

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Known addresses.
var (
	linkLocal = wtFwpV6AddrAndMask{[16]uint8{0xfe, 0x80}, 10}

	linkLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2}}
	siteLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3}}

	linkLocalRouterMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}}
)

func permitTunInterface(session uintptr, baseObjects *baseObjects, weight uint8, ifLUID uint64) error {
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: (uintptr)(unsafe.Pointer(&ifLUID)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&ifaceCondition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// permitApp: everything the program at path sends or receives, on any interface — the csqtt client's own VK/TURN traffic.
// csq-socks: the exe path, and a token with Administrators enabled (the elevated csq-socks that starts it): a program
// that runs the same exe unelevated gets nothing past the kill switch (WireGuard matched its service SID instead).
func permitApp(session uintptr, baseObjects *baseObjects, weight uint8, path string) error {
	appID, err := getAppID(path)
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))
	if err := setAdminBlob(); err != nil {
		return wrapErr(err)
	}

	conditions := [2]wtFwpmFilterCondition0{{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)), // WFP's own memory
		},
	}, {
		fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
			value: uintptr(unsafe.Pointer(&adminBlob)), // a package variable: it never moves
		},
	}}
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     &conditions[0],
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}
	filterID := uint64(0)
	for _, l := range []struct {
		name  string
		layer windows.GUID
	}{
		{"Permit the csqtt client outbound (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4},
		{"Permit the csqtt client inbound (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4},
		{"Permit the csqtt client outbound (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6},
		{"Permit the csqtt client inbound (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6},
	} {
		displayData, err := createWtFwpmDisplayData0(l.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter.displayData = *displayData
		filter.layerKey = l.layer
		if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

// permitLAN: the local network stays reachable while the tunnel is up or blocked (csq-socks; on Linux its routes stay):
// RFC 1918, link-local, multicast and broadcast; on IPv6 link-local
// package variables: the conditions carry their addresses as uintptr, which a moving goroutine stack would leave stale
var (
	lanV4 = [...]wtFwpV4AddrAndMask{
		{0x0A000000, 0xFF000000}, // 10.0.0.0/8
		{0xAC100000, 0xFFF00000}, // 172.16.0.0/12
		{0xC0A80000, 0xFFFF0000}, // 192.168.0.0/16
		{0xA9FE0000, 0xFFFF0000}, // 169.254.0.0/16
		{0xE0000000, 0xF0000000}, // 224.0.0.0/4
		{0xFFFFFFFF, 0xFFFFFFFF}, // 255.255.255.255
	}
	lanV6 = linkLocal
)

func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	v4 := lanV4[:]
	conditions := make([]wtFwpmFilterCondition0, len(v4)) // the same field repeated = any of them
	for i := range v4 {
		conditions[i] = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&v4[i])),
			},
		}
	}
	condition6 := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_V6_ADDR_MASK,
			value: uintptr(unsafe.Pointer(&lanV6)),
		},
	}
	filterID := uint64(0)
	for _, l := range []struct {
		name  string
		layer windows.GUID
		conds []wtFwpmFilterCondition0
	}{
		{"Permit LAN outbound (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, conditions},
		{"Permit LAN inbound (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, conditions},
		{"Permit link-local outbound (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, []wtFwpmFilterCondition0{condition6}},
		{"Permit link-local inbound (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, []wtFwpmFilterCondition0{condition6}},
	} {
		displayData, err := createWtFwpmDisplayData0(l.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            l.layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(l.conds)),
			filterCondition:     &l.conds[0],
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}
		if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

func permitLoopback(session uintptr, baseObjects *baseObjects, weight uint8) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_FLAGS,
		matchType: cFWP_MATCH_FLAGS_ALL_SET,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDHCPIPv4(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv4.
	//
	{
		var conditions [4]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT32
		conditions[3].conditionValue.value = uintptr(0xffffffff)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv4.
	//
	{
		var conditions [3]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDHCPIPv6(session uintptr, baseObjects *baseObjects, weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv6.
	//
	{
		var conditions [6]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalDHCPMulticast))

		// Repeat the condition type for logical OR.
		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[2].conditionValue.value = uintptr(unsafe.Pointer(&siteLocalDHCPMulticast))

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT16
		conditions[3].conditionValue.value = uintptr(547)

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[4].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[5].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[5].matchType = cFWP_MATCH_EQUAL
		conditions[5].conditionValue._type = cFWP_UINT16
		conditions[5].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv6.
	//
	{
		var conditions [5]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(547)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_UINT16
		conditions[4].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitNdp(session uintptr, baseObjects *baseObjects, weight uint8) error {
	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	type filterDefinition struct {
		displayData *wtFwpmDisplayData0
		conditions  []wtFwpmFilterCondition0
		layer       windows.GUID
	}

	var defs []filterDefinition

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(133)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalRouterMulticast))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 133", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(134)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 134", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(135)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 135", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(136)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 136", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(137)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 137", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	for _, definition := range defs {
		filter.displayData = *definition.displayData
		filter.layerKey = definition.layer
		filter.numFilterConditions = uint32(len(definition.conditions))
		filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&definition.conditions[0]))

		err := fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func blockAll(session uintptr, baseObjects *baseObjects, weight uint8) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block outbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block inbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block outbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block inbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all DNS traffic except towards specified DNS servers.
func blockDNS(except []netip.Addr, session uintptr, baseObjects *baseObjects, weightAllow, weightDeny uint8) error {
	if weightDeny >= weightAllow {
		return errors.New("The allow weight must be greater than the deny weight")
	}

	denyConditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(53),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		// Repeat the condition type for logical OR.
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightDeny),
		numFilterConditions: uint32(len(denyConditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&denyConditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block IPv4 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block IPv4 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block IPv6 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block IPv6 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	allowConditionsV4 := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+len(except))
	allowConditionsV4 = append(allowConditionsV4, denyConditions...)
	for _, ip := range except {
		if !ip.Is4() {
			continue
		}
		allowConditionsV4 = append(allowConditionsV4, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT32,
				value: uintptr(binary.BigEndian.Uint32(ip.AsSlice())),
			},
		})
	}

	storedPointers := make([]*wtFwpByteArray16, 0, len(except))
	allowConditionsV6 := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+len(except))
	allowConditionsV6 = append(allowConditionsV6, denyConditions...)
	for _, ip := range except {
		if !ip.Is6() {
			continue
		}
		address := wtFwpByteArray16{byteArray16: ip.As16()}
		allowConditionsV6 = append(allowConditionsV6, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_BYTE_ARRAY16_TYPE,
				value: uintptr(unsafe.Pointer(&address)),
			},
		})
		storedPointers = append(storedPointers, &address)
	}

	filter = wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightAllow),
		numFilterConditions: uint32(len(allowConditionsV4)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV4[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID = uint64(0)

	//
	// #5 Allow IPv4 outbound DNS.
	//
	if len(allowConditionsV4) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #6 Allow IPv4 inbound DNS.
	//
	if len(allowConditionsV4) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV6[0]))
	filter.numFilterConditions = uint32(len(allowConditionsV6))

	//
	// #7 Allow IPv6 outbound DNS.
	//
	if len(allowConditionsV6) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #8 Allow IPv6 inbound DNS.
	//
	if len(allowConditionsV6) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(storedPointers)

	return nil
}
