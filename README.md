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
  -c string
    	expected CIDR range (default "0.0.0.0/0")
  -d string
    	directory where to store the event files, relative to the working directory, if provided (default working directory)
  -f string
    	BPF filter, e.g. "arp and src host not 0.0.0.0" (default "arp")
  -fh string
    	host event filter (default "1111")
  -fp string
    	packet event filter (default "1111")
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
./netreact -i eth0 -d events -fp '0000' -fh '1111'
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
| NEW_PACKET                    | 100        | 10000               |                   |
| NEW_LINK_LOCAL_UNICAST_PACKET | 101        | 01000               |                   |
| NEW_UNSPECIFIED_PACKET        | 102        | 00100               |                   |
| NEW_BROADCAST_PACKET          | 103        | 00010               |                   |
| NEW_UNEXPECTED_IP_PACKET      | 104        | 00001               |                   |
| NEW_HOST                      | 200        |                     | 10000             |
| NEW_LINK_LOCAL_UNICAST_HOST   | 201        |                     | 01000             |
| NEW_UNSPECIFIED_HOST          | 202        |                     | 00100             |
| NEW_BROADCAST_HOST            | 203        |                     | 00010             |
| NEW_UNEXPECTED_IP_HOST        | 204        |                     | 00001             |

Event codes are used in generated filenames only.

Use `-fp` and `-fh` flags to produce event files for selected event types only, e.g.:

```
-fp '00000' -fh '11000'
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

## TODO

- [x] MAC vendor detection
- [x] State file - optionally save the current state to a state file on exit and load when starting next time
- [x] New event type - new host detected
- [x] New event type - link-local unicast source IP address (169.254.0.0/16)
- [x] New event type - 0.0.0.0 source IP address
- [x] New event type - 255.255.255.255 source IP address
- [x] Event type filters
- [x] New event type - unexpected source IP address
- [ ] New event type - new IP address for the same MAC
- [ ] New event type - new MAC address for the same IP
- [ ] Exclusion files - optionally ignore selected IP, MAC or IP-MAC address combinations
- [ ] Schema validation when loading a state file
- [ ] Allow the user to sort the UI table
- [ ] Automatic event file cleanup
