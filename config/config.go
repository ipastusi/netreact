package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
	"golang.org/x/sys/unix"
)

type EventTypeConfig struct {
	Any                 *bool `yaml:"any"`
	NewLinkLocalUnicast *bool `yaml:"newLinkLocalUnicast"`
	NewUnspecified      *bool `yaml:"newUnspecified"`
	NewBroadcast        *bool `yaml:"newBroadcast"`
	NewUnexpected       *bool `yaml:"newUnexpected"`
	NewIpForMac         *bool `yaml:"newIpForMac"`
	NewMacForIp         *bool `yaml:"newMacForIp"`
}

type ExcludeConfig struct {
	IpFile    *string `yaml:"ipFile"`
	MacFile   *string `yaml:"macFile"`
	IpMacFile *string `yaml:"ipMacFile"`
}

type EventsConfig struct {
	Directory           *string          `yaml:"directory"`
	ExpectedCidrRange   *string          `yaml:"expectedCidrRange"`
	AutoCleanupDelaySec *uint            `yaml:"autoCleanupDelaySec"`
	ExcludeConfig       *ExcludeConfig   `yaml:"exclude"`
	PacketEventConfig   *EventTypeConfig `yaml:"packet"`
	HostEventConfig     *EventTypeConfig `yaml:"host"`
}

type Config struct {
	IfaceName     *string       `yaml:"interface"`
	LogFileName   *string       `yaml:"log"`
	StateFileName *string       `yaml:"stateFile"`
	BpfFilter     *string       `yaml:"bpfFilter"`
	PromiscMode   *bool         `yaml:"promiscMode"`
	Ui            *bool         `yaml:"ui"`
	EventsConfig  *EventsConfig `yaml:"events"`
}

func GetConfig(data []byte, iface *string, log *string, prom *bool, state *string) (Config, error) {
	config, err := readConfig(data)
	if err != nil {
		return Config{}, err
	}
	config.applyOverrides(iface, log, prom, state)
	err = config.applyDefaults()
	if err != nil {
		return Config{}, err
	}
	err = config.validate()
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func readConfig(data []byte) (Config, error) {
	config := &Config{}
	err := yaml.UnmarshalWithOptions(data, config, yaml.Strict())
	if err != nil {
		return Config{}, err
	}
	return *config, nil
}

func (cfg *Config) applyOverrides(iface *string, log *string, prom *bool, state *string) {
	if iface != nil {
		cfg.IfaceName = iface
	}
	if log != nil {
		cfg.LogFileName = log
	}
	if prom != nil {
		cfg.PromiscMode = prom
	}
	if state != nil {
		cfg.StateFileName = state
	}
}

func (cfg *Config) applyDefaults() error {
	defaultLog := "netreact.log"
	defaultBpfFilter := "arp"
	defaultExpectedCidrRange := "0.0.0.0/0"
	yes := true
	no := false
	zero := uint(0)

	if cfg.LogFileName == nil {
		cfg.LogFileName = &defaultLog
	}
	if cfg.BpfFilter == nil {
		cfg.BpfFilter = &defaultBpfFilter
	}
	if cfg.PromiscMode == nil {
		cfg.PromiscMode = &no
	}
	if cfg.Ui == nil {
		cfg.Ui = &yes
	}
	if cfg.EventsConfig == nil {
		cfg.EventsConfig = &EventsConfig{}
	}
	if cfg.EventsConfig.AutoCleanupDelaySec == nil {
		cfg.EventsConfig.AutoCleanupDelaySec = &zero
	}

	eventDirPath, err := eventDirPath(cfg.EventsConfig.Directory)
	if err != nil {
		return err
	}
	cfg.EventsConfig.Directory = &eventDirPath

	if cfg.EventsConfig.ExpectedCidrRange == nil {
		cfg.EventsConfig.ExpectedCidrRange = &defaultExpectedCidrRange
	}
	if cfg.EventsConfig.ExcludeConfig == nil {
		cfg.EventsConfig.ExcludeConfig = &ExcludeConfig{}
	}
	if cfg.EventsConfig.PacketEventConfig == nil {
		cfg.EventsConfig.PacketEventConfig = &EventTypeConfig{}
	}
	if cfg.EventsConfig.PacketEventConfig.Any == nil {
		cfg.EventsConfig.PacketEventConfig.Any = &no
	}
	if cfg.EventsConfig.PacketEventConfig.NewLinkLocalUnicast == nil {
		cfg.EventsConfig.PacketEventConfig.NewLinkLocalUnicast = &no
	}
	if cfg.EventsConfig.PacketEventConfig.NewUnspecified == nil {
		cfg.EventsConfig.PacketEventConfig.NewUnspecified = &no
	}
	if cfg.EventsConfig.PacketEventConfig.NewBroadcast == nil {
		cfg.EventsConfig.PacketEventConfig.NewBroadcast = &no
	}
	if cfg.EventsConfig.PacketEventConfig.NewUnexpected == nil {
		cfg.EventsConfig.PacketEventConfig.NewUnexpected = &no
	}
	if cfg.EventsConfig.PacketEventConfig.NewIpForMac == nil {
		cfg.EventsConfig.PacketEventConfig.NewIpForMac = &no
	}
	if cfg.EventsConfig.PacketEventConfig.NewMacForIp == nil {
		cfg.EventsConfig.PacketEventConfig.NewMacForIp = &no
	}
	if cfg.EventsConfig.HostEventConfig == nil {
		cfg.EventsConfig.HostEventConfig = &EventTypeConfig{}
	}
	if cfg.EventsConfig.HostEventConfig.Any == nil {
		cfg.EventsConfig.HostEventConfig.Any = &no
	}
	if cfg.EventsConfig.HostEventConfig.NewLinkLocalUnicast == nil {
		cfg.EventsConfig.HostEventConfig.NewLinkLocalUnicast = &no
	}
	if cfg.EventsConfig.HostEventConfig.NewUnspecified == nil {
		cfg.EventsConfig.HostEventConfig.NewUnspecified = &no
	}
	if cfg.EventsConfig.HostEventConfig.NewBroadcast == nil {
		cfg.EventsConfig.HostEventConfig.NewBroadcast = &no
	}
	if cfg.EventsConfig.HostEventConfig.NewUnexpected == nil {
		cfg.EventsConfig.HostEventConfig.NewUnexpected = &no
	}
	if cfg.EventsConfig.HostEventConfig.NewIpForMac == nil {
		cfg.EventsConfig.HostEventConfig.NewIpForMac = &no
	}
	if cfg.EventsConfig.HostEventConfig.NewMacForIp == nil {
		cfg.EventsConfig.HostEventConfig.NewMacForIp = &no
	}
	return nil
}

func eventDirPath(eventsDirSuffix *string) (string, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	var step string
	if strings.HasSuffix(pwd, "/config") {
		step = ".."
	}

	var suffix string
	if eventsDirSuffix != nil {
		suffix = *eventsDirSuffix
	}

	evendDirPath := filepath.Join(pwd, step, suffix)
	absEventDirPath, err := filepath.Abs(evendDirPath)
	if err != nil {
		return "", err
	}

	return absEventDirPath, nil
}

func (cfg *Config) validate() error {
	if *cfg.IfaceName == "" {
		return fmt.Errorf("no interface name provided")
	} else if _, err := net.InterfaceByName(*cfg.IfaceName); err != nil {
		return err
	} else {
		// we might want to make it work on Windows one day. today is not that day
		if unix.Access(*cfg.EventsConfig.Directory, unix.W_OK) != nil {
			return fmt.Errorf("directory does not exist or is not writable: %v", *cfg.EventsConfig.Directory)
		}
	}

	if ip, _, err := net.ParseCIDR(*cfg.EventsConfig.ExpectedCidrRange); err != nil {
		return fmt.Errorf("invalid expected CIDR range %v: %v", *cfg.EventsConfig.ExpectedCidrRange, err)
	} else if ip.To4() == nil {
		return fmt.Errorf("expected CIDR range should be IPv4, got: %v", ip)
	}

	excludeFiles := []*string{
		cfg.EventsConfig.ExcludeConfig.IpFile,
		cfg.EventsConfig.ExcludeConfig.MacFile,
		cfg.EventsConfig.ExcludeConfig.IpMacFile,
	}
	for _, excludeFile := range excludeFiles {
		if excludeFile != nil {
			if _, err := os.Stat(*excludeFile); err != nil {
				return fmt.Errorf("file does not exist: %v", *excludeFile)
			}
		}
	}

	return nil
}
