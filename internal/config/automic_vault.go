package config

import (
	"fmt"
	"path/filepath"

	. "github.com/microsoft/go-sqlcmd/cmd/modern/sqlconfig"
	"github.com/microsoft/go-sqlcmd/internal/automicvault"
	"github.com/microsoft/go-sqlcmd/internal/secret"
)

var storeCredential = automicvault.Store

func Password(user User, address string, port int) string {
	if user.AuthenticationType != "basic" || user.BasicAuth == nil {
		panic("sqlcmd user is not basic authentication")
	}
	if user.BasicAuth.PasswordEncryption == automicvault.Encryption {
		requireDefaultConfig()
		return automicvault.Password(user.Name, address, port, user.BasicAuth.Password, user.BasicAuth.PasswordEncryption)
	}
	return decryptCallback(user.BasicAuth.Password, user.BasicAuth.PasswordEncryption)
}

func prepareUser(user *User) {
	if !automicvault.IsEnabled() || user.AuthenticationType != "basic" {
		return
	}
	requireDefaultConfig()
	if user.BasicAuth == nil {
		panic("basic sqlcmd user has no authentication details")
	}
	if user.BasicAuth.PasswordEncryption == automicvault.Encryption {
		if user.BasicAuth.Password != automicvault.Marker {
			panic("invalid Automic Vault sqlcmd credential marker")
		}
		return
	}
	plain := secret.Decode(user.BasicAuth.Password, user.BasicAuth.PasswordEncryption)
	storeCredential(user.Name, plain)
	user.BasicAuth.Password = automicvault.Marker
	user.BasicAuth.PasswordEncryption = automicvault.Encryption
}

func HardenWithAutomicVault() []string {
	if !automicvault.IsEnabled() {
		panic("Automic Vault support is unavailable in this sqlcmd build")
	}
	requireDefaultConfig()
	for i := range config.Users {
		if config.Users[i].AuthenticationType != "basic" || config.Users[i].BasicAuth == nil {
			panic(fmt.Sprintf("unsupported sqlcmd authentication for user %q", config.Users[i].Name))
		}
		prepareUser(&config.Users[i])
	}
	Save()
	return AutomicVaultProfiles()
}

func AutomicVaultStatus() (profiles []string, total int, hardened bool) {
	requireDefaultConfig()
	profiles = AutomicVaultProfiles()
	total = len(config.Users)
	hardened = automicvault.IsEnabled() && len(profiles) == total
	for _, user := range config.Users {
		if user.AuthenticationType != "basic" || user.BasicAuth == nil {
			hardened = false
		}
	}
	return
}

func requireDefaultConfig() {
	if filepath.Clean(filename) != filepath.Clean(DefaultFileName()) {
		panic("Automic Vault credentials require the default sqlconfig path")
	}
}

func AutomicVaultProfiles() []string {
	profiles := make([]string, 0, len(config.Users))
	for _, user := range config.Users {
		if user.AuthenticationType == "basic" && user.BasicAuth != nil &&
			user.BasicAuth.PasswordEncryption == automicvault.Encryption &&
			user.BasicAuth.Password == automicvault.Marker {
			profiles = append(profiles, user.Name)
		}
	}
	return profiles
}
