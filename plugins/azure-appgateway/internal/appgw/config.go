package appgw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Config is the per-target settings block from the connector config.
type Config struct {
	// SubscriptionID is the Azure subscription that holds the gateway.
	SubscriptionID string `json:"subscription_id"`
	// ResourceGroup is the gateway's resource group.
	ResourceGroup string `json:"resource_group"`
	// Gateway is the Application Gateway name.
	Gateway string `json:"gateway"`
	// SSLCertificate is the name of the gateway's sslCertificates entry that
	// the listeners use.
	SSLCertificate string `json:"ssl_certificate"`
	// CreateIfMissing adds the sslCertificates entry on the first
	// activation when the gateway does not have it yet. Default false.
	CreateIfMissing bool `json:"create_if_missing"`
}

var (
	subscriptionRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// Resource group names: letters, digits, underscores, hyphens, periods
	// and parentheses, 1 to 90 characters, not ending in a period. Azure
	// also allows other Unicode letters; those are accepted too.
	resourceGroupRE = regexp.MustCompile(`^[\p{L}\p{N}_\-.()]{1,90}$`)
	// Application Gateway and child resource names: 1 to 80 characters,
	// starting with a letter or digit, ending with a letter, digit or
	// underscore, with letters, digits, underscores, periods and hyphens in
	// between.
	resourceNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.\-]{0,78}[A-Za-z0-9_])?$`)
)

// ParseConfig decodes and checks a settings block. Unknown keys are
// rejected so a typo does not go unnoticed. Errors wrap plugin.ErrPermanent.
func ParseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: azure-appgateway settings: %v", plugin.ErrPermanent, err)
	}
	if problems := c.problems(); len(problems) > 0 {
		return Config{}, fmt.Errorf("%w: azure-appgateway settings: %s", plugin.ErrPermanent, strings.Join(problems, "; "))
	}
	return c, nil
}

func (c Config) problems() []string {
	var p []string
	switch {
	case c.SubscriptionID == "":
		p = append(p, "subscription_id is required")
	case !subscriptionRE.MatchString(c.SubscriptionID):
		p = append(p, fmt.Sprintf("subscription_id %q is not a subscription id (a GUID)", c.SubscriptionID))
	}
	switch {
	case c.ResourceGroup == "":
		p = append(p, "resource_group is required")
	case !resourceGroupRE.MatchString(c.ResourceGroup) || strings.HasSuffix(c.ResourceGroup, "."):
		p = append(p, fmt.Sprintf("resource_group %q is not a valid resource group name", c.ResourceGroup))
	}
	switch {
	case c.Gateway == "":
		p = append(p, "gateway is required")
	case !resourceNameRE.MatchString(c.Gateway):
		p = append(p, fmt.Sprintf("gateway %q is not a valid Application Gateway name", c.Gateway))
	}
	switch {
	case c.SSLCertificate == "":
		p = append(p, "ssl_certificate is required")
	case !resourceNameRE.MatchString(c.SSLCertificate):
		p = append(p, fmt.Sprintf("ssl_certificate %q is not a valid certificate name", c.SSLCertificate))
	}
	return p
}
