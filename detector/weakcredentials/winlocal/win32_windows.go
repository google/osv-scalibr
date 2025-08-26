// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package winlocal

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapiDLL    = syscall.NewLazyDLL("Advapi32.dll")
	regSaveKeyEx = advapiDLL.NewProc("RegSaveKeyExW")
)

func securityAttributesFromSDDL(sddl string) (*windows.SecurityAttributes, error) {
	if sddl == "" {
		return nil, nil
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	return sa, nil
}

// RegSaveKey wraps the `RegSaveKeyExW` Win32 API to save a registry key to a file.
//
// Note: sddl is optional. If empty, the security attribute will be null and the file will get a
// default security descriptor.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsavekeyexw
//
// LSTATUS RegSaveKeyExW(
//
//	[in]           HKEY                        hKey,
//	[in]           LPCWSTR                     lpFile,
//	[in, optional] const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//	[in]           DWORD                       Flags
//
// );
func RegSaveKey(key syscall.Handle, path string, sddl string) error {
	if regSaveKeyEx == nil {
		return errors.New("cannot find RegSaveKeyExW in Advapi32.dll")
	}

	securityAttributes, err := securityAttributesFromSDDL(sddl)
	if err != nil {
		return err
	}

	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	// Note: we enforce the `Flags` parameter to be 1 (REG_STANDARD_FORMAT) to always use the standard
	// registry format.
	flags := uintptr(1)
	hKey := uintptr(key)
	lpFile := uintptr(unsafe.Pointer(p))
	lpSecurityAttributes := uintptr(unsafe.Pointer(securityAttributes))

	if ret, _, _ := regSaveKeyEx.Call(hKey, lpFile, lpSecurityAttributes, flags); ret != 0 {
		return syscall.Errno(ret)
	}

	return nil
}
