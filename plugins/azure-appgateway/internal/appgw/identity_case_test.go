package appgw

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
)

// The Azure CLI creates identities with type "userAssigned" and ARM returns
// it in that case; templates use "UserAssigned". Both must be accepted.
func TestIdentityProblemTypeCase(t *testing.T) {
	ids := map[string]*armnetwork.ManagedServiceIdentityUserAssignedIdentities{
		"/subscriptions/s/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id": {},
	}
	for _, typ := range []string{"userAssigned", "UserAssigned", "SystemAssigned, UserAssigned"} {
		gw := &armnetwork.ApplicationGateway{Identity: &armnetwork.ManagedServiceIdentity{
			Type:                   to.Ptr(armnetwork.ResourceIdentityType(typ)),
			UserAssignedIdentities: ids,
		}}
		if p := identityProblem(gw); p != "" {
			t.Errorf("type %q: got problem %q", typ, p)
		}
	}
	if p := identityProblem(&armnetwork.ApplicationGateway{}); p == "" {
		t.Error("no identity: want a problem")
	}
}
