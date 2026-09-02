package automicvault

import (
	"context"
	"os/exec"
	"testing"
)

func TestGetUsesFixedHelperRoute(t *testing.T) {
	oldEnabled, oldCommand := Enabled, command
	Enabled = "true"
	command = func(_ context.Context, name string, args ...string) *exec.Cmd {
		if name != "/usr/local/bin/av" || len(args) != 5 || args[0] != "sqlcmd-credential" || args[1] != "get" || args[2] != "prod" || args[3] != "db.example.com" || args[4] != "1433" {
			t.Fatalf("unexpected helper invocation: %s %v", name, args)
		}
		return exec.Command("/usr/bin/printf", "password")
	}
	t.Cleanup(func() { Enabled, command = oldEnabled, oldCommand })
	if got := Password("prod", "db.example.com", 1433, Marker, Encryption); got != "password" {
		t.Fatalf("Password() = %q", got)
	}
}

func TestInputsFailClosed(t *testing.T) {
	for _, test := range []func(){
		func() { validateProfile(" bad") },
		func() { validateEndpoint("", 1433) },
		func() { validateEndpoint("db", 65536) },
		func() { validateSecret("line\nbreak") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid input did not panic")
				}
			}()
			test()
		}()
	}
}
