package oui

import (
	"cmp"
	_ "embed"
	"encoding/hex"
	"net"
	"slices"
	"strings"
)

// There is no perfect solution for MAC vendor lookup. Options include:
// - Separate OUI lookup file distributed separately, which will introduce a new dependency.
// - Separate OUI lookup file distributed with netreact, which will require one more file in addition to the binary.
// - Embedding the OUI lookup data directly into the Go code, which will cause IDE to freeze due to its size.
// - Embedding the OUI lookup data the way it is done now, which will load more data into memory.
// - Perform the OUI lookup using an online service, which would require internet egress and be against Netreact being a 100% passive tool.

//go:embed oui.txt
var ouiRaw string

var ouiList = strings.Split(ouiRaw, "\n")

func MacToVendor(mac net.HardwareAddr) string {
	oui := hex.EncodeToString(mac[:3])
	i, ok := slices.BinarySearchFunc(ouiList, oui, func(str, target string) int {
		return cmp.Compare(str[:6], target)
	})

	if !ok {
		return "Unknown"
	}

	vendorName := ouiList[i][7:]
	return strings.TrimSpace(vendorName)
}
