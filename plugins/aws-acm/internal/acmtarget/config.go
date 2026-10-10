package acmtarget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Config is the target block from the connector config, without the keys
// the core owns.
type Config struct {
	// Region is the AWS region of the ACM certificate, for example
	// us-east-1. It must match the region in CertificateARN.
	Region string `json:"region"`
	// CertificateARN is the imported ACM certificate to re-import into.
	CertificateARN string `json:"certificate_arn"`
}

// arn is the parsed form of an ACM certificate ARN:
// arn:<partition>:acm:<region>:<account>:certificate/<id>.
type arn struct {
	Partition, Region, Account, ID string
}

func parseARN(s string) (arn, error) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "acm" {
		return arn{}, fmt.Errorf("certificate_arn %q is not an ACM certificate ARN (arn:aws:acm:<region>:<account>:certificate/<id>)", s)
	}
	id, ok := strings.CutPrefix(parts[5], "certificate/")
	if !ok || id == "" || parts[1] == "" || parts[3] == "" || parts[4] == "" {
		return arn{}, fmt.Errorf("certificate_arn %q is not an ACM certificate ARN (arn:aws:acm:<region>:<account>:certificate/<id>)", s)
	}
	return arn{Partition: parts[1], Region: parts[3], Account: parts[4], ID: id}, nil
}

// parseConfig decodes and checks the settings. Unknown keys are refused so
// a typo does not go unnoticed.
func parseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return c, fmt.Errorf("settings are not a JSON object: %w", err)
	}
	if _, ok := keys["create_if_missing"]; ok {
		return c, errors.New("create_if_missing is not supported: import the first certificate yourself and set certificate_arn (see the plugin README)")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("settings: %w", err)
	}
	c.Region = strings.TrimSpace(c.Region)
	c.CertificateARN = strings.TrimSpace(c.CertificateARN)
	var problems []string
	if c.Region == "" {
		problems = append(problems, "region is required")
	}
	if c.CertificateARN == "" {
		problems = append(problems, "certificate_arn is required")
	} else if a, err := parseARN(c.CertificateARN); err != nil {
		problems = append(problems, err.Error())
	} else if c.Region != "" && a.Region != c.Region {
		problems = append(problems, fmt.Sprintf("region %s does not match the region in certificate_arn (%s); ACM certificates are regional", c.Region, a.Region))
	}
	if len(problems) > 0 {
		return c, errors.New(strings.Join(problems, "; "))
	}
	return c, nil
}
