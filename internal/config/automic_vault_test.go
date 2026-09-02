package config

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/microsoft/go-sqlcmd/cmd/modern/sqlconfig"
	"github.com/microsoft/go-sqlcmd/internal/automicvault"
	"github.com/microsoft/go-sqlcmd/internal/secret"
)

func TestHardenWithAutomicVaultStoresBeforeReplacingPasswords(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	SetFileName(filepath.Join(home, ".sqlcmd", "sqlconfig"))
	config = Sqlconfig{Users: []User{{
		Name: "prod", AuthenticationType: "basic",
		BasicAuth: &BasicAuthDetails{Username: "sa", Password: secret.Encode("password", "none"), PasswordEncryption: "none"},
	}}}
	oldEnabled, oldStore := automicvault.Enabled, storeCredential
	automicvault.Enabled = "true"
	stored := false
	storeCredential = func(profile, password string) {
		if profile != "prod" || password != "password" {
			t.Fatalf("unexpected store: %q %q", profile, password)
		}
		stored = true
	}
	t.Cleanup(func() {
		automicvault.Enabled, storeCredential = oldEnabled, oldStore
		config = Sqlconfig{}
		_ = os.RemoveAll(filepath.Join(home, ".sqlcmd"))
	})
	profiles := HardenWithAutomicVault()
	if !stored || len(profiles) != 1 || profiles[0] != "prod" {
		t.Fatalf("migration failed: %v", profiles)
	}
	if got := config.Users[0].BasicAuth; got.Password != automicvault.Marker || got.PasswordEncryption != automicvault.Encryption {
		t.Fatalf("plaintext remained in config: %#v", got)
	}
}
