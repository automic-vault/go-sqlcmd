// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package automicvault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	Encryption = "av"
	Marker     = "@av"
	maxSecret  = 64 * 1024
)

// Enabled is set only by the reviewed Automic Vault Isotope build.
var Enabled = "false"

var command = exec.CommandContext

func IsEnabled() bool { return Enabled == "true" }

func Password(profile, address string, port int, stored, encryption string) string {
	if encryption != Encryption {
		return ""
	}
	if !IsEnabled() || stored != Marker {
		panic("invalid Automic Vault sqlcmd credential marker")
	}
	validateProfile(profile)
	validateEndpoint(address, port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(ctx, "/usr/local/bin/av", "sqlcmd-credential", "get", profile, address, strconv.Itoa(port))
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		panic(fmt.Sprintf("failed to read sqlcmd password from Automic Vault: %v", err))
	}
	password := strings.TrimSuffix(string(out), "\n")
	validateSecret(password)
	return password
}

func Store(profile, password string) {
	if !IsEnabled() {
		return
	}
	validateProfile(profile)
	validateSecret(password)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(ctx, "/usr/local/bin/av", "sqlcmd-credential", "store", profile)
	cmd.Stdin = strings.NewReader(password)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("failed to store sqlcmd password in Automic Vault: %v", err))
	}
}

func Forget(profile string) {
	if !IsEnabled() {
		return
	}
	validateProfile(profile)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(ctx, "/usr/local/bin/av", "sqlcmd-credential", "forget", profile)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("failed to delete sqlcmd password from Automic Vault: %v", err))
	}
}

func validateProfile(value string) {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || !isASCII(value) {
		panic("invalid sqlcmd user profile")
	}
}

func validateEndpoint(address string, port int) {
	if address == "" && port == 0 {
		return
	}
	if address == "" || len(address) > 253 || strings.TrimSpace(address) != address || !isASCII(address) || port < 0 || port > 65535 {
		panic("invalid sqlcmd endpoint")
	}
}

func validateSecret(value string) {
	if value == "" || len(value) > maxSecret || strings.ContainsAny(value, "\x00\r\n") {
		panic("invalid sqlcmd password")
	}
}

func isASCII(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r > 0x7e }) == -1
}
