package container

import (
	"encoding/json"
	"fmt"
)

type PolicyType int

type PolicyMap map[PolicyType]string

const (
	NetworkFireWallPolicy PolicyType = iota
	NetworkPriorityPolicy
	NetworkBandwidthPolicy
	NetworkLoadbalancePolicy
	StorageRatelimitPolicy
	StorageSnapshotPolicy
)

var AllowedPolicyTypes = map[PolicyType]string{
	NetworkFireWallPolicy:    "network-firewall-policy",
	NetworkPriorityPolicy:    "network-priority-policy",
	NetworkBandwidthPolicy:   "network-bandwidth-policy",
	NetworkLoadbalancePolicy: "network-loadbalance-policy",
	StorageRatelimitPolicy:   "storage-ratelimit-policy",
	StorageSnapshotPolicy:    "storage-snapshot-policy",
}

var AllowedPolicyStrings = map[string]PolicyType{
	"network-firewall-policy":    NetworkFireWallPolicy,
	"network-priority-policy":    NetworkPriorityPolicy,
	"network-bandwidth-policy":   NetworkBandwidthPolicy,
	"network-loadbalance-policy": NetworkLoadbalancePolicy,
	"storage-ratelimit-policy":   StorageRatelimitPolicy,
	"storage-snapshot-policy":    StorageSnapshotPolicy,
}

func (pt PolicyType) IsValidType() bool {
	_, ok := AllowedPolicyTypes[pt]
	return ok
}

func (pt PolicyType) String() string {
	str, ok := AllowedPolicyTypes[pt]
	if !ok {
		return "undefined"
	}
	return str
}

func (pt PolicyType) MarshalJSON() ([]byte, error) {
	if !pt.IsValidType() {
		return nil, fmt.Errorf("unsupported policy type: %d", pt)
	}
	return json.Marshal(pt.String())
}

func (pt PolicyType) UnmarshalJSON(in []byte) error {
	v, ok := AllowedPolicyStrings[string(in)]
	if !ok {
		return fmt.Errorf("unsupported policy string: %q", in)
	}
	pt = v
	return nil
}

func (pm PolicyMap) MarshalJSON() ([]byte, error) {
	m := make(map[string]string)
	for k, v := range pm {
		if !k.IsValidType() {
			return nil, fmt.Errorf("unsupported policy type: %d", k)
		}
		m[k.String()] = v
	}
	return json.Marshal(m)
}

func (pm PolicyMap) UnmarshalJSON(in []byte) error {
	m := make(map[string]string)
	if err := json.Unmarshal(in, &m); err != nil {
		return err
	}
	for k, v := range m {
		pt, ok := AllowedPolicyStrings[k]
		if !ok {
			return fmt.Errorf("unsupported policy string: %q", in)
		}
		pm[pt] = v
	}
	return nil
}
