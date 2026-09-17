//go:build windows

package connectorhost

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

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
