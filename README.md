# Netreact

Passive ARP scanner with built-in support for generating event notifications. Inspired by other ARP tools and some real-life events in my
home network.

[![Go](https://github.com/ipastusi/netreact/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ipastusi/netreact/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ipastusi/netreact/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/ipastusi/netreact/actions/workflows/codeql-analysis.yml)

![image](images/netreact-ui.png)

## Overview

Once started, Netreact will passively listen to ARP traffic, and:

- Update the user interface every time a new packet is received, unless you decided to disable the user interface using the `-u=false` flag.
- Log to `netreact.log` using JSON Lines format. Log file name can be customised using the `-l` flag.
- Create a separate event file for each event. File names will match `netreact-<unix_timestamp>.json` pattern, e.g.
  `netreact-1747995770259.json`. By default the files will be created in the working directory. However, you are encouraged to specify a
  custom directory using the `-d` flag.

Sample event file:

```json
{
  "eventType": "ARP_PACKET_RECEIVED",
  "ip": "192.168.8.100",
  "mac": "f8:4e:73:2d:1c:8a",
  "firstTs": 1749464243156,
  "ts": 1749464246164,
  "count": 5,
  "macVendor": "Apple, Inc."
}
```

Event details:

- `eventType` - currently only `ARP_PACKET_RECEIVED` is supported.
- `ip` - ARP packet source IP address.
- `mac` - ARP packet source MAC address.
- `firstTs` - Unix timestamp of when this IP-MAC combination was first seen, in milliseconds. It will be the same as the current timestamp
  if the count is equal to 1.
- `ts` - Unix timestamp of when the ARP packet was received, in milliseconds.
- `count` - Number of packets with this IP-MAC combination seen so far.
- `macVendor` - Vendor name for the MAC address OUI. `Unknown` if not found.

## Quick start guide

Build:

```
go build
```

If the build fails, you may need to install `libpcap-dev` or similar, depending on your Linux distribution.

Help:

```
./netreact -h
Usage of ./netreact:
  -d string
    	directory where to store the event files, relative to the working directory, if provided (default working directory)
  -f string
    	custom BPF filter, e.g. "arp and src host not 0.0.0.0" (default "arp")
  -i string
    	interface name, e.g. eth0
  -l string
    	log file (default "netreact.log")
  -p	put the interface in promiscuous mode (default false)
  -s string
    	state file (default none)
  -u	display textual user interface (default true)
```

Examples:

```
./netreact -i eth0 -d events
./netreact -i eth0 -d events -f 'arp and src host not 0.0.0.0'
./netreact -i eth0 -d events -u=false
./netreact -i eth0 -d events -s nrstate.json
```

## Event files

Event files offer you the ability to trigger custom responses to detected ARP events. You can implement arbitrary event file detection
mechanism and response logic.

On Linux you might want to use `inotifywait` to detect event file creation:

```
./netreact -i eth0 -d events

inotifywait -qme close_write events/ --format %w%f | parallel -u echo
events/netreact-1747995770259.json
events/netreact-1747995770270.json
events/netreact-1747995770292.json
```

On macOS you might want to use `fswatch`:

```
./netreact -i en0 -d events

fswatch --event Created events/ | xargs -n 1 -I _ echo _
/path/to/netreact/events/netreact-1747995770294.json
/path/to/netreact/events/netreact-1747995770336.json
/path/to/netreact/events/netreact-1747995771602.json
```

## State file

`-s` flag allows you to define a JSON state file to / from which to save / load data. It allows you to persist the collected data between
executions.

## MAC vendor lookup

Netreact ships with its own embedded MAC OUI database for MAC vendor lookup, based on publicly available MA-L data (see [oui.txt](oui.txt)).
No external files or online services are required at runtime.

## TODO

- [x] MAC vendor detection
- [x] State file - optionally save the current state to a state file on exit and load when starting next time
- [ ] Allow the user to sort the UI table
- [ ] Exclusion files - optionally ignore selected IP, MAC or IP-MAC address combinations
- [ ] New event type - new host detected
- [ ] New event type - unexpected source IP address
- [ ] New event type - link-local source IP address (169.254.0.0/16)
- [ ] New event type - 0.0.0.0 source IP address
- [ ] New event type - new IP address for the same MAC
- [ ] New event type - new MAC address for the same IP
- [ ] Schema validation when loading a state file
