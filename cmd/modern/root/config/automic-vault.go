package config

import (
	"encoding/json"
	"fmt"

	"github.com/microsoft/go-sqlcmd/internal/cmdparser"
	internalconfig "github.com/microsoft/go-sqlcmd/internal/config"
)

type AutomicVault struct {
	cmdparser.Cmd
	status bool
}

func (c *AutomicVault) DefineCommand(...cmdparser.CommandOptions) {
	c.Cmd.DefineCommand(cmdparser.CommandOptions{
		Use:   "automic-vault",
		Short: "Move sqlcmd passwords into Automic Vault",
		Run:   c.run,
	})
	c.AddFlag(cmdparser.FlagOptions{
		Name: "status", Bool: &c.status,
		Usage: "Report Automic Vault credential status without changing configuration",
	})
}

func (c *AutomicVault) run() {
	profiles, total, hardened := internalconfig.AutomicVaultStatus()
	if !c.status {
		profiles = internalconfig.HardenWithAutomicVault()
		total, hardened = len(profiles), true
	}
	data, err := json.Marshal(struct {
		Profiles []string `json:"profiles"`
		Total    int      `json:"total_users"`
		Hardened bool     `json:"hardened"`
	}{profiles, total, hardened})
	c.CheckErr(err)
	fmt.Println(string(data))
}
