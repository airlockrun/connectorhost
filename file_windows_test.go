//go:build windows

package connectorhost

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestControlDescriptorSharesRenameAccess(t *testing.T) {
	root := t.TempDir()
	token, err := randomControlSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomControlSecret(24)
	if err != nil {
		t.Fatal(err)
	}
	want := ControlDescriptor{Protocol: controlProtocol, Port: 12345, Token: token, PID: os.Getpid(), Nonce: nonce}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "unpublished")
	if err := atomicWrite(source, body, 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(source)
	if err != nil {
		t.Fatal(err)
	}
	// Keep rename access open after publication to exercise sharing deterministically.
	handle, err := windows.CreateFile(name, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := replaceFile(source, filepath.Join(root, controlDescriptor)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadControlDescriptor(root)
	if err != nil || got != want {
		t.Fatalf("read during rename: %+v, %v", got, err)
	}
}

func TestSharedReaderAllowsAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot")
	if err := atomicWrite(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := openSharedRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := atomicWrite(path, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "before" {
		t.Fatalf("open snapshot = %q, %v", body, err)
	}
	body, err = os.ReadFile(path)
	if err != nil || string(body) != "after" {
		t.Fatalf("replacement = %q, %v", body, err)
	}
}

func TestAtomicWritePreservesPrivateACL(t *testing.T) {
	root := t.TempDir()
	// A permissive parent makes inherited access observable if publication loses
	// the temporary file's protected DACL.
	parent, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := parent.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	reference := filepath.Join(root, "reference")
	if err := os.WriteFile(reference, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureFile(reference); err != nil {
		t.Fatal(err)
	}
	want, err := windows.GetNamedSecurityInfo(reference, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []bool{false, true} {
		name := "create"
		if existing {
			name = "replace"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			if existing {
				if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := atomicWrite(path, []byte("private"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			control, _, err := got.Control()
			if err != nil {
				t.Fatal(err)
			}
			if control&windows.SE_DACL_PROTECTED == 0 || got.String() != want.String() {
				t.Fatalf("published DACL = %s (control %#x), want protected %s", got.String(), control, want.String())
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "private" {
				t.Fatalf("published content = %q, %v", body, err)
			}
		})
	}
}
