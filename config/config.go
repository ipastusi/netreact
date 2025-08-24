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
		return config, err
	}
	config.applyOverrides(iface, log, prom, state)
	config.applyDefaults()
	err = config.resolveAbsPaths()
	if err != nil {
		return config, err
	}
	err = config.validate()
	return config, err
}

func readConfig(data []byte) (Config, error) {
	config := &Config{}
	err := yaml.UnmarshalWithOptions(data, config, yaml.Strict())
	return *config, err
}

func (cfg *Config) applyOverrides(iface *string, log *string, prom *bool, state *string) {
	applyIfNotNilOrEmpty(&cfg.IfaceName, iface)
	applyIfNotNil(&cfg.LogFileName, log)
	applyIfNotNil(&cfg.PromiscMode, prom)
	applyIfNotNilOrEmpty(&cfg.StateFileName, state)
}

func (cfg *Config) resolveAbsPaths() error {
	err := resolveIfNotNil(&cfg.LogFileName)
	if err != nil {
		return err
	}
	err = resolveIfNotNil(&cfg.StateFileName)
	if err != nil {
		return err
	}
	err = resolveIfNotNil(&cfg.EventsConfig.Directory)
	return err
}

func (cfg *Config) applyDefaults() {
	applyToNil(&cfg.BpfFilter, "arp")
	applyToNil(&cfg.PromiscMode, false)
	applyToNil(&cfg.Ui, true)
	applyToNil(&cfg.EventsConfig, EventsConfig{})
	applyToNil(&cfg.EventsConfig.AutoCleanupDelaySec, 0)
	applyToNil(&cfg.EventsConfig.ExpectedCidrRange, "0.0.0.0/0")
	applyToNil(&cfg.EventsConfig.Directory, "")
	applyToNil(&cfg.EventsConfig.ExcludeConfig, ExcludeConfig{})

	applyToNil(&cfg.EventsConfig.PacketEventConfig, EventTypeConfig{})
	applyToNil(&cfg.EventsConfig.PacketEventConfig.Any, false)
	applyToNil(&cfg.EventsConfig.PacketEventConfig.NewLinkLocalUnicast, false)
	applyToNil(&cfg.EventsConfig.PacketEventConfig.NewUnspecified, false)
	applyToNil(&cfg.EventsConfig.PacketEventConfig.NewBroadcast, false)
	applyToNil(&cfg.EventsConfig.PacketEventConfig.NewUnexpected, false)
	applyToNil(&cfg.EventsConfig.PacketEventConfig.NewIpForMac, false)
	applyToNil(&cfg.EventsConfig.PacketEventConfig.NewMacForIp, false)

	applyToNil(&cfg.EventsConfig.HostEventConfig, EventTypeConfig{})
	applyToNil(&cfg.EventsConfig.HostEventConfig.Any, false)
	applyToNil(&cfg.EventsConfig.HostEventConfig.NewLinkLocalUnicast, false)
	applyToNil(&cfg.EventsConfig.HostEventConfig.NewUnspecified, false)
	applyToNil(&cfg.EventsConfig.HostEventConfig.NewBroadcast, false)
	applyToNil(&cfg.EventsConfig.HostEventConfig.NewUnexpected, false)
	applyToNil(&cfg.EventsConfig.HostEventConfig.NewIpForMac, false)
	applyToNil(&cfg.EventsConfig.HostEventConfig.NewMacForIp, false)
}

func (cfg *Config) validate() error {
	if cfg.IfaceName == nil {
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

func applyIfNotNilOrEmpty(ptr **string, value *string) {
	if value != nil && *value != "" {
		*ptr = value
	}
}

func applyIfNotNil[T any](ptr **T, value *T) {
	if value != nil {
		*ptr = value
	}
}

func resolveIfNotNil(ptr **string) error {
	if *ptr != nil {
		absPath, err := toAbsPath(*ptr)
		if err != nil {
			return err
		}
		*ptr = &absPath
	}
	return nil
}

func toAbsPath(path *string) (string, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	var step string
	// when running unit tests for this package
	if strings.HasSuffix(pwd, "/config") {
		step = ".."
	}

	var suffix string
	if path != nil {
		suffix = *path
	}

	absPath := filepath.Join(pwd, step, suffix)
	return absPath, nil
}

func applyToNil[T any](ptr **T, value T) {
	if *ptr == nil {
		*ptr = &value
	}
}
