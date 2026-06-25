// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestFlattenTrustedNetwork_allFields(t *testing.T) {
	networkID := "net-123"
	networkName := "Office WiFi"
	interfaceType := int32(1)
	isDefault := true
	rev := int32(5)
	orgID := "org-456"
	createdAt := "2025-01-01T00:00:00Z"
	modifiedAt := "2025-06-01T12:00:00Z"

	tn := &ztnaprofiles.TrustedNetwork{
		NetworkId:      &networkID,
		NetworkName:    &networkName,
		InterfaceType:  &interfaceType,
		IsDefault:      &isDefault,
		Rev:            &rev,
		OrganizationId: &orgID,
		CreatedAt:      &createdAt,
		ModifiedAt:     &modifiedAt,
		Criteria: &ztnaprofiles.TrustedNetworkCriteria{
			DnsServers:     []ztnaprofiles.DnsServer{{ServerIp: "8.8.8.8"}},
			DnsDomains:     []ztnaprofiles.DnsDomain{{Name: "corp.example.com"}},
			TrustedServers: []ztnaprofiles.TrustedServer{{Url: "https://trust.example.com"}},
		},
	}

	var m ztnaTrustedNetworkModel
	flattenTrustedNetwork(tn, &m)

	if m.ID.ValueString() != "net-123" {
		t.Errorf("ID = %q, want %q", m.ID.ValueString(), "net-123")
	}
	if m.NetworkName.ValueString() != "Office WiFi" {
		t.Errorf("NetworkName = %q, want %q", m.NetworkName.ValueString(), "Office WiFi")
	}
	if m.InterfaceType.ValueInt64() != 1 {
		t.Errorf("InterfaceType = %d, want 1", m.InterfaceType.ValueInt64())
	}
	if m.IsDefault.ValueBool() != true {
		t.Errorf("IsDefault = %v, want true", m.IsDefault.ValueBool())
	}
	if m.Rev.ValueInt64() != 5 {
		t.Errorf("Rev = %d, want 5", m.Rev.ValueInt64())
	}
	if m.OrganizationId.ValueString() != "org-456" {
		t.Errorf("OrganizationId = %q, want %q", m.OrganizationId.ValueString(), "org-456")
	}
	if m.CreatedAt.ValueString() != "2025-01-01T00:00:00Z" {
		t.Errorf("CreatedAt = %q, want %q", m.CreatedAt.ValueString(), "2025-01-01T00:00:00Z")
	}
	if m.ModifiedAt.ValueString() != "2025-06-01T12:00:00Z" {
		t.Errorf("ModifiedAt = %q, want %q", m.ModifiedAt.ValueString(), "2025-06-01T12:00:00Z")
	}
	if m.Criteria == nil {
		t.Fatal("Criteria is nil")
	}
	if len(m.Criteria.DnsServers) != 1 || m.Criteria.DnsServers[0].ServerIp.ValueString() != "8.8.8.8" {
		t.Errorf("DnsServers mismatch")
	}
	if len(m.Criteria.DnsDomains) != 1 || m.Criteria.DnsDomains[0].Name.ValueString() != "corp.example.com" {
		t.Errorf("DnsDomains mismatch")
	}
	if len(m.Criteria.TrustedServers) != 1 || m.Criteria.TrustedServers[0].Url.ValueString() != "https://trust.example.com" {
		t.Errorf("TrustedServers mismatch")
	}
}

func TestFlattenTrustedNetwork_nilFields(t *testing.T) {
	tn := &ztnaprofiles.TrustedNetwork{}
	var m ztnaTrustedNetworkModel
	flattenTrustedNetwork(tn, &m)

	if !m.ID.IsNull() && m.ID.ValueString() != "" {
		t.Errorf("ID should be zero value, got %q", m.ID.ValueString())
	}
	if m.Criteria != nil {
		t.Errorf("Criteria should be nil when input has no criteria")
	}
}

func TestFlattenTrustedNetworkCriteria_nil(t *testing.T) {
	result := flattenTrustedNetworkCriteria(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestFlattenTrustedNetworkCriteria_empty(t *testing.T) {
	c := &ztnaprofiles.TrustedNetworkCriteria{}
	result := flattenTrustedNetworkCriteria(c)
	if result == nil {
		t.Fatal("expected non-nil result for empty criteria")
	}
	if len(result.DnsServers) != 0 {
		t.Errorf("DnsServers = %d, want 0", len(result.DnsServers))
	}
	if len(result.DnsDomains) != 0 {
		t.Errorf("DnsDomains = %d, want 0", len(result.DnsDomains))
	}
	if len(result.TrustedServers) != 0 {
		t.Errorf("TrustedServers = %d, want 0", len(result.TrustedServers))
	}
}

func TestFlattenTrustedNetworkCriteria_withCertificateHash(t *testing.T) {
	hash := "sha256:abc123"
	c := &ztnaprofiles.TrustedNetworkCriteria{
		TrustedServers: []ztnaprofiles.TrustedServer{
			{Url: "https://a.example.com", CertificateHash: &hash},
			{Url: "https://b.example.com", CertificateHash: nil},
		},
	}

	result := flattenTrustedNetworkCriteria(c)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.TrustedServers) != 2 {
		t.Fatalf("TrustedServers length = %d, want 2", len(result.TrustedServers))
	}
	if result.TrustedServers[0].CertificateHash.ValueString() != "sha256:abc123" {
		t.Errorf("first server hash = %q, want %q", result.TrustedServers[0].CertificateHash.ValueString(), "sha256:abc123")
	}
	if !result.TrustedServers[1].CertificateHash.IsNull() {
		t.Errorf("second server hash should be null, got %q", result.TrustedServers[1].CertificateHash.ValueString())
	}
}

func TestExpandTrustedNetworkCriteria_nil(t *testing.T) {
	result := expandTrustedNetworkCriteria(nil)
	if len(result.DnsServers) != 0 || len(result.DnsDomains) != 0 || len(result.TrustedServers) != 0 {
		t.Error("expected empty criteria for nil input")
	}
}

func TestExpandTrustedNetworkCriteria_roundTrip(t *testing.T) {
	hash := "sha256:deadbeef"
	input := &ztnaTrustedNetCriteria{
		DnsServers: []ztnaDnsServerModel{
			{ServerIp: types.StringValue("1.1.1.1")},
			{ServerIp: types.StringValue("8.8.4.4")},
		},
		DnsDomains: []ztnaDnsDomainModel{
			{Name: types.StringValue("corp.local")},
		},
		TrustedServers: []ztnaTrustedServerModel{
			{Url: types.StringValue("https://verify.corp.local"), CertificateHash: types.StringValue(hash)},
			{Url: types.StringValue("https://backup.corp.local"), CertificateHash: types.StringNull()},
		},
	}

	expanded := expandTrustedNetworkCriteria(input)

	if len(expanded.DnsServers) != 2 {
		t.Fatalf("DnsServers length = %d, want 2", len(expanded.DnsServers))
	}
	if expanded.DnsServers[0].ServerIp != "1.1.1.1" {
		t.Errorf("DnsServers[0] = %q, want %q", expanded.DnsServers[0].ServerIp, "1.1.1.1")
	}
	if expanded.DnsServers[1].ServerIp != "8.8.4.4" {
		t.Errorf("DnsServers[1] = %q, want %q", expanded.DnsServers[1].ServerIp, "8.8.4.4")
	}
	if len(expanded.DnsDomains) != 1 || expanded.DnsDomains[0].Name != "corp.local" {
		t.Errorf("DnsDomains mismatch")
	}
	if len(expanded.TrustedServers) != 2 {
		t.Fatalf("TrustedServers length = %d, want 2", len(expanded.TrustedServers))
	}
	if expanded.TrustedServers[0].Url != "https://verify.corp.local" {
		t.Errorf("TrustedServers[0].Url = %q", expanded.TrustedServers[0].Url)
	}
	if expanded.TrustedServers[0].CertificateHash == nil || *expanded.TrustedServers[0].CertificateHash != hash {
		t.Errorf("TrustedServers[0].CertificateHash = %v, want %q", expanded.TrustedServers[0].CertificateHash, hash)
	}
	if expanded.TrustedServers[1].CertificateHash != nil {
		t.Errorf("TrustedServers[1].CertificateHash should be nil, got %v", expanded.TrustedServers[1].CertificateHash)
	}
}
