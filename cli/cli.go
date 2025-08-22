package cli

import (
	"flag"
)

type Flags struct {
	ConfigFileName *string
	IfaceName      *string
	LogFileName    *string
	StateFileName  *string
	PromiscMode    *bool
	RenderConfig   *bool
}

func GetFlags() Flags {
	configFileName := flag.String("c", "", "YAML config file (default none)")
	ifaceName := flag.String("i", "", "interface name, e.g. eth0")
	logFileName := flag.String("l", "netreact.log", "log file")
	promisc := flag.Bool("p", false, "put the interface in promiscuous mode (default false)")
	renderConfig := flag.Bool("r", false, "render config and exit (default false)")
	stateFileName := flag.String("s", "", "state file (default none)")

	flag.Parse()
	flags := Flags{
		ConfigFileName: configFileName,
		IfaceName:      ifaceName,
		LogFileName:    logFileName,
		PromiscMode:    promisc,
		RenderConfig:   renderConfig,
		StateFileName:  stateFileName,
	}
	return flags
}
