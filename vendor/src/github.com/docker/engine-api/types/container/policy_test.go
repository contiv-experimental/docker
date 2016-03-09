package container

import (
	"encoding/json"
	"sort"
	"testing"

	. "github.com/go-check/check"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type PolicyTestSuite struct {
}

var _ = Suite(&PolicyTestSuite{})

type sortedAttrs []PolicyAttribute

func (sa sortedAttrs) Len() int {
	return len(sa)
}

func (sa sortedAttrs) Less(i, j int) bool {
	return sa[i].Type() < sa[j].Type()
}

func (sa sortedAttrs) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

type PoliciesSlc []Policy

func (s *PolicyTestSuite) TestPolicyMarshal(c *C) {
	p := struct {
		Policies []Policy `json:"Policies"`
	}{
		Policies: []Policy{
			{
				Category:         "foo",
				CategoryInstance: "bar",
				Attributes: []PolicyAttribute{
					NewNetworkCOSAttr(1),
					NewNetworkBandwidthAttr("bw100"),
					NewNetworkFirewallAttr(),
					NewNetworkVendorSpecificAttr("vendor1"),
				},
			},
		},
	}

	exptdOut := `{
		"Policies" :[{
		"category": "foo",
		"category_instance": "bar",
		"attributes": [
			{
				"type": "vendor-specific",
				"data": "vendor1"
			},
			{
				"type": "cos",
				"data": 1
			},
			{
				"type": "bandwidth",
				"data": "bw100"
			},
			{
				"type": "firewall",
				"data": {
					"rules": [],
					"groupId": ""
				}
			}
		]
	}]}`

	out, err := json.Marshal(p)
	c.Assert(err, IsNil)
	var (
		oJSON map[string]interface{}
		eJSON map[string]interface{}
	)
	c.Assert(json.Unmarshal(out, &oJSON), IsNil)
	c.Assert(json.Unmarshal([]byte(exptdOut), &eJSON), IsNil)
	//DeepEquals will not work as is because the attributes in the slice
	// are not in a particular order, so we resort to a more manual comparison
	c.Assert(len(oJSON), Equals, len(eJSON))
	c.Assert(oJSON["Policies"], FitsTypeOf, eJSON["Policies"])
	oPolicy := oJSON["Policies"].([]interface{})[0].(map[string]interface{})
	ePolicy := eJSON["Policies"].([]interface{})[0].(map[string]interface{})
	c.Assert(oPolicy["category"], Equals, ePolicy["category"])
	c.Assert(oPolicy["category_instance"], Equals, ePolicy["category_instance"])
	c.Assert(oPolicy["attributes"], FitsTypeOf, ePolicy["attributes"])
	oAttrs := oPolicy["attributes"].([]interface{})
	eAttrs := ePolicy["attributes"].([]interface{})
	c.Assert(len(oAttrs), Equals, len(eAttrs))
	for i := range oAttrs {
		matches := false
		for j := range eAttrs {

			if matches, _ = DeepEquals.Check([]interface{}{oAttrs[i], eAttrs[j]}, []string{}); matches {
				break
			}
		}
		c.Assert(matches, Equals, true,
			Commentf("output attr: %+v not found in expected attrs %+v", oAttrs[i], eAttrs))
	}
}

func (s *PolicyTestSuite) TestPolicyUnmarshal(c *C) {
	policies := `[{
		"category": "foo",
		"category_instance": "bar",
		"attributes": [
			{
				"type": "vendor-specific",
				"data": "vendor1"
			},
			{
				"type": "cos",
				"data": 1
			},
			{
				"type": "bandwidth",
				"data": "bw100"
			},
			{
				"type": "firewall",
				"data": {
					"rules": [],
					"groupId": ""
				}
			}
		]
	}]`

	ePolicy := &Policy{
		Category:         "foo",
		CategoryInstance: "bar",
		Attributes: []PolicyAttribute{
			NewNetworkCOSAttr(1),
			NewNetworkBandwidthAttr("bw100"),
			NewNetworkFirewallAttr(),
			NewNetworkVendorSpecificAttr("vendor1"),
		},
	}

	oPolicies := []*Policy{}
	c.Assert(json.Unmarshal([]byte(policies), &oPolicies), IsNil)
	//DeepEquals will not work as is because the attributes in the slice
	// are not in a particular order, so we resort to a more manual comparison
	oPolicy := oPolicies[0]
	c.Assert(oPolicy.Category, Equals, ePolicy.Category)
	c.Assert(oPolicy.CategoryInstance, Equals, ePolicy.CategoryInstance)
	oAttrsSorted := sortedAttrs(oPolicy.Attributes)
	sort.Sort(oAttrsSorted)
	eAttrsSorted := sortedAttrs(ePolicy.Attributes)
	sort.Sort(eAttrsSorted)
	c.Assert(len(oAttrsSorted), Equals, len(eAttrsSorted))
	for i := range oAttrsSorted {
		c.Assert(oAttrsSorted[i], DeepEquals, eAttrsSorted[i])
	}
}
