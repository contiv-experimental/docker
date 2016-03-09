package container

import (
	"encoding/json"
	"fmt"
)

const (
	NetworkFirewallAttrType       = "firewall"
	NetworkBandwidthAttrType      = "bandwidth"
	NetworkCOSAttrType            = "cos"
	NetworkVendorSpecificAttrType = "vendor-specific"
)

var AllowedPolicyAttributes = map[string]bool{
	NetworkFirewallAttrType:       true,
	NetworkBandwidthAttrType:      true,
	NetworkCOSAttrType:            true,
	NetworkVendorSpecificAttrType: true,
}

func InvalidPolicyAttributeStringError(rcvd, exptd string) error {
	return fmt.Errorf("invalid policy attribute string: %q. Expected: %q", rcvd, exptd)
}

type firewallRule struct {
	direction   string
	action      string
	protocol    string
	port        string
	peerGroupId string
	peerCIDR    string
}

// NetworkFirewallAttr defines a security policy that is collection of
// actions for traffic matching L3/L4 protocol and L4 port
type NetworkFirewallAttr struct {
	rules   []firewallRule
	groupId string
}

func NewNetworkFirewallAttr() *NetworkFirewallAttr {
	return &NetworkFirewallAttr{rules: []firewallRule{}}
}

func (fw *NetworkFirewallAttr) AddRule(direction, action, protocol, port, peerGroupId, peerCIDR string) {
	fw.rules = append(fw.rules, firewallRule{
		direction:   direction,
		action:      action,
		protocol:    protocol,
		port:        port,
		peerGroupId: peerGroupId,
		peerCIDR:    peerCIDR,
	})
}

func (fw *NetworkFirewallAttr) Type() string {
	return NetworkFirewallAttrType
}

func (fw *NetworkFirewallAttr) MarshalJSON() ([]byte, error) {
	// local type for marshalling
	type forJSON struct {
		Direction   string `json:"direction"`
		Action      string `json:"action"`
		Protocol    string `json: "protocol"`
		Port        string `json:"port"`
		PeerGroupId string `json:"peerGroupId"`
		PeerCIDR    string `json:"peerCIDR"`
	}
	rules := []forJSON{}

	for _, r := range fw.rules {
		rules = append(rules, forJSON{
			Direction:   r.direction,
			Action:      r.action,
			Protocol:    r.protocol,
			Port:        r.port,
			PeerGroupId: r.peerGroupId,
			PeerCIDR:    r.peerCIDR,
		})
	}

	return json.Marshal(struct {
		Type string `json:"type"`
		Data struct {
			Rules   []forJSON `json:"rules"`
			GroupId string    `json:"groupId"`
		} `json:"data"`
	}{
		Type: NetworkFirewallAttrType,
		Data: struct {
			Rules   []forJSON `json:"rules"`
			GroupId string    `json:"groupId"`
		}{
			Rules:   rules,
			GroupId: fw.groupId,
		},
	})
}

func (fw *NetworkFirewallAttr) UnmarshalJSON(in []byte) error {
	// local type for marshalling
	type forJSON struct {
		Type string `json:"type"`
		Data struct {
			GroupId string `json:"groupId"`
			Rules   []struct {
				Direction   string `json:"direction"`
				Action      string `json:"action"`
				Protocol    string `json: "protocol"`
				Port        string `json:"port"`
				PeerGroupId string `json:"peerGroupId"`
				PeerCIDR    string `json:"peerCIDR"`
			} `json:"rules"`
		} `json:"data"`
	}

	val := forJSON{}
	if err := json.Unmarshal(in, &val); err != nil {
		return err
	}

	if val.Type != NetworkFirewallAttrType {
		return InvalidPolicyAttributeStringError(val.Type, NetworkFirewallAttrType)
	}

	fw.groupId = val.Data.GroupId
	for _, r := range val.Data.Rules {
		fw.AddRule(r.Direction, r.Action, r.Protocol, r.Port, r.PeerGroupId, r.PeerCIDR)
	}
	return nil
}

// NetworkBandwidthAttr defines a  policy that controls the bandwidth
// available for traffic originating from the endpoint in a network
type NetworkBandwidthAttr string

func NewNetworkBandwidthAttr(bw string) *NetworkBandwidthAttr {
	val := NetworkBandwidthAttr(bw)
	return &val
}

func (bw *NetworkBandwidthAttr) Type() string {
	return NetworkBandwidthAttrType
}

func (bw *NetworkBandwidthAttr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}{
		Type: NetworkBandwidthAttrType,
		Data: string(*bw),
	})
}

func (bw *NetworkBandwidthAttr) UnmarshalJSON(in []byte) error {
	val := struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}{}

	if err := json.Unmarshal(in, &val); err != nil {
		return err
	}

	if val.Type != NetworkBandwidthAttrType {
		return InvalidPolicyAttributeStringError(val.Type, NetworkBandwidthAttrType)
	}

	*bw = NetworkBandwidthAttr(val.Data)
	return nil
}

// NetworkCOSAttr defines a  policy that controls the class of service
// applied for traffic originating from the endpoint in a network
type NetworkCOSAttr int

func NewNetworkCOSAttr(cos int) *NetworkCOSAttr {
	val := NetworkCOSAttr(cos)
	return &val
}

func (cos *NetworkCOSAttr) Type() string {
	return NetworkCOSAttrType
}

func (cos *NetworkCOSAttr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Data int    `json:"data"`
	}{
		Type: NetworkCOSAttrType,
		Data: int(*cos),
	})
}

func (cos *NetworkCOSAttr) UnmarshalJSON(in []byte) error {
	val := struct {
		Type string `json:"type"`
		Data int    `json:"data"`
	}{}

	if err := json.Unmarshal(in, &val); err != nil {
		return err
	}

	if val.Type != NetworkCOSAttrType {
		return InvalidPolicyAttributeStringError(val.Type, NetworkCOSAttrType)
	}

	*cos = NetworkCOSAttr(val.Data)
	return nil
}

// NetworkVendorSpecificAttr defines a vendor specific policy label that allows
// to apply vendor specific polices for traffic originating from the
// endpoint in a network
type NetworkVendorSpecificAttr string

func NewNetworkVendorSpecificAttr(vs string) *NetworkVendorSpecificAttr {
	val := NetworkVendorSpecificAttr(vs)
	return &val
}

func (vs *NetworkVendorSpecificAttr) Type() string {
	return NetworkVendorSpecificAttrType
}

func (vs *NetworkVendorSpecificAttr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}{
		Type: NetworkVendorSpecificAttrType,
		Data: string(*vs),
	})
}

func (vs *NetworkVendorSpecificAttr) UnmarshalJSON(in []byte) error {
	val := struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}{}

	if err := json.Unmarshal(in, &val); err != nil {
		return err
	}

	if val.Type != NetworkVendorSpecificAttrType {
		return InvalidPolicyAttributeStringError(val.Type, NetworkVendorSpecificAttrType)
	}

	*vs = NetworkVendorSpecificAttr(val.Data)
	return nil
}
