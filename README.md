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
- Create event files in JSON format. File names will match `netreact-<unix_timestamp>-<event_code>.json` pattern,
  e.g. `netreact-1747995770259-100.json`. See section below for more info.

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
  -a uint
    	auto cleanup generated event files after n seconds (default 0, disabled)
  -c string
    	expected CIDR range (default "0.0.0.0/0")
  -d string
    	directory where to store the event files, relative to the working directory, if provided (default working directory)
  -ei string
    	file with excluded IP addresses
  -em string
    	file with excluded MAC addresses
  -ep string
    	file with excluded IP-MAC address pairs
  -f string
    	BPF filter, e.g. "arp and src host not 0.0.0.0" (default "arp")
  -fh string
    	host event filter (default "1111111")
  -fp string
    	packet event filter (default "1111111")
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
./netreact -i eth0 -d events -fp '0000000' -fh '1111111'
```

## State file

`-s` flag allows you to define a JSON state file to / from which to save / load data. It allows you to persist the collected data between
executions.

## MAC vendor lookup

Netreact ships with its own embedded MAC OUI database for MAC vendor lookup, based on publicly available MA-L data (see [oui.txt](oui.txt)).
No external files or online services are required at runtime.

## Event files

Netreact can generate the following types of events:

| Event type                    | Event code | Packet event filter | Host event filter |
|-------------------------------|------------|---------------------|-------------------|
| NEW_PACKET                    | 100        | 1000000             |                   |
| NEW_LINK_LOCAL_UNICAST_PACKET | 101        | 0100000             |                   |
| NEW_UNSPECIFIED_PACKET        | 102        | 0010000             |                   |
| NEW_BROADCAST_PACKET          | 103        | 0001000             |                   |
| NEW_UNEXPECTED_IP_PACKET      | 104        | 0000100             |                   |
| NEW_IP_FOR_MAC_PACKET         | 105        | 0000010             |                   |
| NEW_MAC_FOR_IP_PACKET         | 106        | 0000001             |                   |
| NEW_HOST                      | 200        |                     | 1000000           |
| NEW_LINK_LOCAL_UNICAST_HOST   | 201        |                     | 0100000           |
| NEW_UNSPECIFIED_HOST          | 202        |                     | 0010000           |
| NEW_BROADCAST_HOST            | 203        |                     | 0001000           |
| NEW_UNEXPECTED_IP_HOST        | 204        |                     | 0000100           |
| NEW_IP_FOR_MAC_HOST           | 205        |                     | 0000010           |
| NEW_MAC_FOR_IP_HOST           | 206        |                     | 0000001           |

Event codes are used in generated filenames only.

Use `-fp` and `-fh` flags to produce event files for selected event types only, e.g.:

```
-fp '0000000' -fh '1100000'
```

The above configuration will prevent Netreact from emiting any packet-related events, while emiting only `NEW_HOST` and
`NEW_LINK_LOCAL_UNICAST_HOST` host-related events.

### Packet-related events

Packet-related event types are triggered every time when a given packet is received. Event codes are 1xx.
Format of packet-related event files (eventType will differ):

```json
{
  "eventType": "NEW_PACKET",
  "ip": "192.168.8.100",
  "mac": "f8:4e:73:2d:1c:8a",
  "firstTs": 1749464243156,
  "ts": 1749464246164,
  "count": 5,
  "macVendor": "Apple, Inc.",
  "expectedCidrRange": "0.0.0.0/0"
}
```

### Host-related events

Host-related event types will be triggered only once per host first time given packet is received. Event codes are 2xx.
Format of packet-related event files (eventType will differ):

```json
{
  "eventType": "NEW_HOST",
  "ip": "192.168.8.100",
  "mac": "f8:4e:73:2d:1c:8a",
  "ts": 1749464246164,
  "macVendor": "Apple, Inc.",
  "expectedCidrRange": "0.0.0.0/0"
}
```

### Event details

Event details will depend on the event type:

- `eventType` - One of the supported event types.
- `ip` - ARP packet source IP address.
- `mac` - ARP packet source MAC address.
- `firstTs` - Unix timestamp of when this IP-MAC combination was first seen, in milliseconds.
- `ts` - Unix timestamp of when the ARP packet was received, in milliseconds.
- `count` - Number of packets with this IP-MAC combination seen so far.
- `macVendor` - Vendor name for the MAC address OUI. `Unknown` if not found.
- `expectedCidrRange` - Expected CIDR range.
- `otherIps` - Other IP addresses recorded previously for this MAC.
- `otherMacs` - Other MAC addresses recorded previously for this IP.

## Event handling

Event files offer you the ability to trigger custom responses to the ARP events. You can implement arbitrary event file detection
mechanism and response logic.

On Linux you might want to use `inotifywait` to detect event file creation:

```
./netreact -i eth0 -d events

inotifywait -qme close_write events/ --format %w%f | parallel -u echo
events/netreact-1747995770259-100.json
events/netreact-1747995770270-100.json
events/netreact-1747995770292-100.json
```

On macOS you might want to use `fswatch`:

```
./netreact -i en0 -d events

fswatch --event Created events/ | xargs -n 1 -I _ echo _
/path/to/netreact/events/netreact-1747995770294-100.json
/path/to/netreact/events/netreact-1747995770336-100.json
/path/to/netreact/events/netreact-1747995771602-100.json
```

If you are using Netreact on macOS with automatic cleanup of generated event files enabled using `-a` flag, and `fswatch` incorrectly 
reports file deletion as `Created` events, you might want to increase the cleanup delay to e.g. 30 seconds. See 
[fswatch #144](https://github.com/emcrisostomo/fswatch/issues/144#issuecomment-264135666).
