package event

type Notification struct {
	// IP and MAC addresses are stored as strings due to:
	// https://github.com/golang/go/issues/29678
	EventType         string   `json:"eventType"`
	Ip                string   `json:"ip"`
	Mac               string   `json:"mac"`
	FirstTs           int64    `json:"firstTs,omitempty"`
	Ts                int64    `json:"ts"`
	Count             int      `json:"count,omitempty"`
	MacVendor         string   `json:"macVendor"`
	ExpectedCidrRange string   `json:"expectedCidrRange"`
	OtherIps          []string `json:"otherIps,omitempty"`
	OtherMacs         []string `json:"otherMacs,omitempty"`
}
