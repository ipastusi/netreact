package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	iface, _      = net.InterfaceByIndex(1)
	customLog     = "custom.log"
	defaultLog    = "netreact.log"
	state         = "nrstate.json"
	defaultFilter = "arp"
	customFilter  = "arp and src host not 0.0.0.0"
	customDir     = getDir("out")
	defaultDir    = getDir("")
	defaultCidr   = "0.0.0.0/0"
	customCidr    = "192.168.0.0/24"
	yes           = true
	no            = false
	_0            = uint(0)
	_30           = uint(30)
)

func Test_GetConfigCustom(t *testing.T) {
	t.Parallel()

	data := []byte(`
log: custom.log
promiscMode: true
stateFile: nrstate.json
bpfFilter: arp and src host not 0.0.0.0
ui: false
events:
  directory: out
  autoCleanupDelaySec: 30
  expectedCidrRange: 192.168.0.0/24
  packet:
    any: true
    newLinkLocalUnicast: true
    newUnspecified: true
    newBroadcast: true
    newUnexpected: true
    newIpForMac: true
    newMacForIp: true
  host:
    any: true
    newLinkLocalUnicast: true
    newUnspecified: true
    newBroadcast: true
    newUnexpected: true
    newIpForMac: true
    newMacForIp: true
`)

	c, err := GetConfig(data, &iface.Name, nil, nil, nil)
	if err != nil {
		t.Fatalf("Error loading yaml: %v", err)
	}

	expC := Config{
		IfaceName:     &iface.Name,
		LogFileName:   &customLog,
		PromiscMode:   &yes,
		StateFileName: &state,
		BpfFilter:     &customFilter,
		Ui:            &no,
		EventsConfig: &EventsConfig{
			Directory:           &customDir,
			ExpectedCidrRange:   &customCidr,
			AutoCleanupDelaySec: &_30,
			ExcludeConfig:       &ExcludeConfig{},
			PacketEventConfig: &EventTypeConfig{
				Any:                 &yes,
				NewLinkLocalUnicast: &yes,
				NewUnspecified:      &yes,
				NewBroadcast:        &yes,
				NewUnexpected:       &yes,
				NewIpForMac:         &yes,
				NewMacForIp:         &yes,
			},
			HostEventConfig: &EventTypeConfig{
				Any:                 &yes,
				NewLinkLocalUnicast: &yes,
				NewUnspecified:      &yes,
				NewBroadcast:        &yes,
				NewUnexpected:       &yes,
				NewIpForMac:         &yes,
				NewMacForIp:         &yes,
			},
		},
	}

	diff := cmp.Diff(c, expC)
	if diff != "" {
		t.Fatalf("Custom structs differ: %v", diff)
	}
}

func Test_GetConfigEmpty(t *testing.T) {
	t.Parallel()

	data := []byte(``)

	c, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err != nil {
		t.Fatalf("Error loading yaml: %v", err)
	}

	expC := Config{
		IfaceName:     &iface.Name,
		LogFileName:   &defaultLog,
		StateFileName: &state,
		BpfFilter:     &defaultFilter,
		PromiscMode:   &yes,
		Ui:            &yes,
		EventsConfig: &EventsConfig{
			Directory:           &defaultDir,
			ExpectedCidrRange:   &defaultCidr,
			AutoCleanupDelaySec: &_0,
			ExcludeConfig:       &ExcludeConfig{},
			PacketEventConfig: &EventTypeConfig{
				Any:                 &no,
				NewLinkLocalUnicast: &no,
				NewUnspecified:      &no,
				NewBroadcast:        &no,
				NewUnexpected:       &no,
				NewIpForMac:         &no,
				NewMacForIp:         &no,
			},
			HostEventConfig: &EventTypeConfig{
				Any:                 &no,
				NewLinkLocalUnicast: &no,
				NewUnspecified:      &no,
				NewBroadcast:        &no,
				NewUnexpected:       &no,
				NewIpForMac:         &no,
				NewMacForIp:         &no,
			},
		},
	}

	diff := cmp.Diff(c, expC)
	if diff != "" {
		t.Fatalf("Custom structs differ: %v", diff)
	}
}

func Test_GetConfigPartial(t *testing.T) {
	t.Parallel()

	data := []byte(`
promiscMode: true
bpfFilter: arp and src host not 0.0.0.0
events:
  directory: out

  expectedCidrRange: 192.168.0.0/24
  packet:
    newLinkLocalUnicast: true
    newBroadcast: true
    newIpForMac: true
`)
	c, err := GetConfig(data, &iface.Name, nil, nil, nil)
	if err != nil {
		t.Fatalf("Error loading yaml: %v", err)
	}

	expC := Config{
		IfaceName:   &iface.Name,
		LogFileName: &defaultLog,
		PromiscMode: &yes,
		BpfFilter:   &customFilter,
		Ui:          &yes,
		EventsConfig: &EventsConfig{
			Directory:           &customDir,
			ExpectedCidrRange:   &customCidr,
			AutoCleanupDelaySec: &_0,
			ExcludeConfig:       &ExcludeConfig{},
			PacketEventConfig: &EventTypeConfig{
				Any:                 &no,
				NewLinkLocalUnicast: &yes,
				NewUnspecified:      &no,
				NewBroadcast:        &yes,
				NewUnexpected:       &no,
				NewIpForMac:         &yes,
				NewMacForIp:         &no,
			},
			HostEventConfig: &EventTypeConfig{
				Any:                 &no,
				NewLinkLocalUnicast: &no,
				NewUnspecified:      &no,
				NewBroadcast:        &no,
				NewUnexpected:       &no,
				NewIpForMac:         &no,
				NewMacForIp:         &no,
			},
		},
	}

	diff := cmp.Diff(c, expC)
	if diff != "" {
		t.Fatalf("Custom structs differ: %v", diff)
	}
}

func Test_GetConfigExtraProperty(t *testing.T) {
	t.Parallel()

	data := []byte(`
extraProperty: unexpected
log: custom.log
promiscMode: true
stateFile: nrstate.json
bpfFilter: arp and src host not 0.0.0.0
ui: false
events:
  directory: out
  autoCleanupDelaySec: 30
  expectedCidrRange: 192.168.0.0/24
  exclude:
    ipFile: ip.txt
    macFile: mac.txt
    ipMacFile: ip_mac.txt
  packet:
    any: true
    newLinkLocalUnicast: true
    newUnspecified: true
    newBroadcast: true
    newUnexpected: true
    newIpForMac: true
    newMacForIp: true
  host:
    any: true
    newLinkLocalUnicast: true
    newUnspecified: true
    newBroadcast: true
    newUnexpected: true
    newIpForMac: true
    newMacForIp: true
`)
	_, err := GetConfig(data, &iface.Name, nil, nil, nil)
	if err == nil {
		t.Fatal("No error when loading yaml with extra property")
	}
}

func Test_GetConfigMissingIface(t *testing.T) {
	t.Parallel()

	data := []byte(``)
	ifaceName := ""
	_, err := GetConfig(data, &ifaceName, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigNonexistentIface(t *testing.T) {
	t.Parallel()

	data := []byte(``)
	ifaceName := "nonexistent"
	_, err := GetConfig(data, &ifaceName, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigNonexistentEventDir(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  directory: nonexistent`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigInvalidCidrRange1(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  expectedCidrRange: 2001:db8::/32`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigInvalidCidrRange2(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  expectedCidrRange: 0.0.0.0/33`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigInvalidCidrRange3(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  expectedCidrRange: invalid`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigNonexistentExcludeIpFile(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  exclude:
    ipFile: nonexistent.txt`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigNonexistentExcludeMacFile(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  exclude:
    macFile: nonexistent.txt`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func Test_GetConfigNonexistentExcludeIpMacFile(t *testing.T) {
	t.Parallel()

	data := []byte(`events:
  exclude:
    ipMacFile: nonexistent.txt`)
	_, err := GetConfig(data, &iface.Name, nil, &yes, &state)
	if err == nil {
		t.Fatal("No error on invalid data")
	}
}

func getDir(path string) string {
	pwd, _ := os.Getwd()
	evendDirPath := filepath.Join(pwd, "..", path)
	absEventDirPath, _ := filepath.Abs(evendDirPath)
	return absEventDirPath
}
