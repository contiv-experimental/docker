package container

import (
	"encoding/json"
	"fmt"
)

// PolicyAttribute defines the value of granular policy construct identified
// by Type. Network bandwidth, quality of service are a few examples of network
// policy attributes
type PolicyAttribute interface {
	json.Marshaler
	json.Unmarshaler
	Type() string
}

// Policy is a collection policy attributes associated with a category like
// network or storage. The CategoryInstance is the identifier for a single instance
// of the Category for the which policy attributes are meant. For instace, for a
// network policy this will be the name of the network to which the policy applies.
type Policy struct {
	Category         string            `json:"category"`
	CategoryInstance string            `json:"category_instance"`
	Attributes       []PolicyAttribute `json:"attributes"`
}

func (p *Policy) UnmarshalJSON(in []byte) error {
	val := struct {
		Category         string `json:"category"`
		CategoryInstance string `json:"category_instance"`
		Attributes       []struct {
			Type string      `json:"type"`
			Data interface{} `json:"data"`
		} `json:"attributes"`
	}{}

	if err := json.Unmarshal(in, &val); err != nil {
		return err
	}

	p.Category = val.Category
	p.CategoryInstance = val.CategoryInstance
	var attr PolicyAttribute
	for _, a := range val.Attributes {
		switch a.Type {
		case NetworkFirewallAttrType:
			attr = NewNetworkFirewallAttr()
		case NetworkBandwidthAttrType:
			attr = NewNetworkBandwidthAttr("")
		case NetworkCOSAttrType:
			attr = NewNetworkCOSAttr(0)
		case NetworkVendorSpecificAttrType:
			attr = NewNetworkVendorSpecificAttr("")
		default:
			return fmt.Errorf("invalid policy attribute type %q", a.Type)
		}
		aBytes, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(aBytes, &attr); err != nil {
			return err
		}
		p.Attributes = append(p.Attributes, attr)
	}
	return nil
}
