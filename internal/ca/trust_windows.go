package ca

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Thumbprint returns the SHA-1 fingerprint of the CA certificate, formatted
// the way certutil reports it (uppercase hex, no separators). Windows uses
// this value to identify a certificate inside a store.
func (c *CA) Thumbprint() string {
	sum := sha1.Sum(c.Cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// openUserRoot opens the current user's Trusted Root certificate store.
func openUserRoot(flags uint32) (windows.Handle, error) {
	root, err := windows.UTF16PtrFromString("Root")
	if err != nil {
		return 0, err
	}
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER|flags, uintptr(unsafe.Pointer(root)))
}

// IsTrusted reports whether this exact CA certificate is in the current
// user's Trusted Root store.
func (c *CA) IsTrusted() bool {
	store, err := openUserRoot(windows.CERT_STORE_READONLY_FLAG)
	if err != nil {
		return false
	}
	defer windows.CertCloseStore(store, 0)

	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev) // frees prev
		if err != nil || ctx == nil {
			return false
		}
		if bytes.Equal(unsafe.Slice(ctx.EncodedCert, ctx.Length), c.Cert.Raw) {
			windows.CertFreeCertificateContext(ctx)
			return true
		}
		prev = ctx
	}
}

// InstallTrust adds the CA certificate to the current user's Trusted Root
// store so that leaf certificates signed by it are accepted by Windows and
// Chromium-based browsers (which use the Windows store).
//
// It uses the Windows certificate API directly rather than certutil: adding a
// root makes Windows show its "Security Warning — install this certificate?"
// dialog, and certutil launched from a no-console app never surfaced that
// dialog. This call blocks until the user answers; declining returns an error.
//
// Firefox keeps its own certificate database and does not consult the Windows
// store by default.
func (c *CA) InstallTrust() error {
	if c.IsTrusted() {
		return nil
	}
	store, err := openUserRoot(0)
	if err != nil {
		return fmt.Errorf("open CurrentUser\\Root: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	ctx, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &c.Cert.Raw[0], uint32(len(c.Cert.Raw)))
	if err != nil {
		return fmt.Errorf("create certificate context: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
		return fmt.Errorf("add to CurrentUser\\Root (declined?): %w", err)
	}
	return nil
}

// UninstallTrust removes the CA certificate from the current user's Trusted
// Root store. Used on clean uninstall.
func (c *CA) UninstallTrust() error {
	cmd := exec.Command("certutil", "-user", "-delstore", "Root", c.Thumbprint())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil del-store failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
