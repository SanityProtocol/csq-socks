/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * csq-socks: getAppID takes the exe path; the service security descriptor is gone.
 */

package firewall

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runTransaction(session uintptr, operation wfpObjectInstaller) error {
	err := fwpmTransactionBegin0(session, 0)
	if err != nil {
		return wrapErr(err)
	}

	err = operation(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	err = fwpmTransactionCommit0(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	return nil
}

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, wrapErr(err)
	}

	return &wtFwpmDisplayData0{
		name:        namePtr,
		description: descriptionPtr,
	}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}

func wrapErr(err error) error {
	if _, ok := err.(syscall.Errno); !ok {
		return err
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("Firewall error at unknown location: %w", err)
	}
	return fmt.Errorf("Firewall error at %s:%d: %w", file, line, err)
}

func getAppID(path string) (*wtFwpByteBlob, error) {
	filePtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, wrapErr(err)
	}

	var appID *wtFwpByteBlob
	err = fwpmGetAppIdFromFileName0(filePtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, wrapErr(err)
	}
	return appID, nil
}

// adminBlob: a security descriptor that lets a token match only while BUILTIN\Administrators is enabled in it — an
// elevated process. An unelevated one holds that group deny-only, which grants nothing. Package variables, so the
// uintptr a filter condition holds stays valid.
var (
	adminSD   *windows.SECURITY_DESCRIPTOR
	adminBlob wtFwpByteBlob
)

func setAdminBlob() error {
	if adminSD != nil {
		return nil
	}
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return wrapErr(err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: cFWP_ACTRL_MATCH_FILTER,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return wrapErr(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return wrapErr(err)
	}
	if err := sd.SetDACL(dacl, true, false); err != nil {
		return wrapErr(err)
	}
	if sd, err = sd.ToSelfRelative(); err != nil {
		return wrapErr(err)
	}
	adminSD = sd
	adminBlob = wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
	return nil
}
