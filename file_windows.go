//go:build windows

package connectorhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(from, to string) error {
	fromPointer, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPointer, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileEx.Call(uintptr(unsafe.Pointer(fromPointer)), uintptr(unsafe.Pointer(toPointer)), 0x1|0x8)
	if result == 0 {
		return fmt.Errorf("MoveFileExW: %w", callErr)
	}
	return nil
}
func syncDirectory(string) error { return nil }

func secureDirectory(path string) error { return setCurrentUserACL(path, true) }
func secureFile(path string) error      { return setCurrentUserACL(path, false) }

func setCurrentUserACL(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	sids := []*windows.SID{user.User.Sid}
	managed, err := isManagedWindowsServicePath(path)
	if err != nil {
		return err
	}
	if managed {
		service, _, _, serviceErr := windows.LookupSID("", `NT SERVICE\AirlockHost`)
		if serviceErr == nil {
			sids = append(sids, service)
		} else if !errors.Is(serviceErr, windows.ERROR_NONE_MAPPED) {
			return serviceErr
		}
	}
	sids = append(sids, administrators, system)
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for i, sid := range sids {
		duplicate := false
		for _, entry := range sids[:i] {
			if sid.Equals(entry) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func isManagedWindowsServicePath(path string) (bool, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return false, err
	}
	root := filepath.Clean(filepath.Join(programData, "Airlock", "Host"))
	path, err = filepath.Abs(path)
	if err != nil {
		return false, err
	}
	path = filepath.Clean(path)
	if strings.EqualFold(path, root) {
		return true, nil
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false, err
	}
	return relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)), nil
}
