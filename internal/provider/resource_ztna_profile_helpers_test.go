// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func ptr[T any](v T) *T { return &v }

func TestFlattenZtnaProfile_allFields(t *testing.T) {
	profile := &ztnaprofiles.ZtnaProfile{
		ProfileId:      ptr("prof-abc"),
		ProfileName:    ptr("Test Profile"),
		Priority:       ptr(int32(10)),
		Rev:            ptr(int32(3)),
		OrganizationId: ptr("org-xyz"),
		CreatedAt:      ptr("2025-01-01T00:00:00Z"),
		ModifiedAt:     ptr("2025-06-15T12:00:00Z"),
		SecurePrivateAccess: &ztnaprofiles.ZtnaProfileSecurePrivateAccessMetadata{
			TrustedNetworksEnabled: ptr(true),
			EnforcementPause: &ztnaprofiles.ZtnaEnforcementPause{
				Enabled:         ptr(true),
				DurationMinutes: ptr(int32(30)),
			},
			DnsSteeringDestinations: []ztnaprofiles.DnsSteeringDestination{
				{Id: ptr("dest-1")},
				{Id: ptr("dest-2")},
			},
		},
		SecureInternetAccess: &ztnaprofiles.ZtnaProfileSecureInternetAccessMetadata{
			SteeringMode:           ptr(int32(2)),
			TrustedNetworksEnabled: ptr(false),
			EnforcementPause: &ztnaprofiles.ZtnaEnforcementPause{
				Enabled:         ptr(false),
				DurationMinutes: ptr(int32(60)),
			},
		},
		UsersData: &ztnaprofiles.ZtnaProfileUsersMetadata{
			AllUsersEnabled: ptr(true),
		},
		GroupsData: &ztnaprofiles.ZtnaProfileGroupsMetadata{
			AllGroupsEnabled: ptr(false),
		},
	}

	var m ztnaProfileModel
	flattenZtnaProfile(profile, &m)

	if m.ID.ValueString() != "prof-abc" {
		t.Errorf("ID = %q, want %q", m.ID.ValueString(), "prof-abc")
	}
	if m.ProfileName.ValueString() != "Test Profile" {
		t.Errorf("ProfileName = %q, want %q", m.ProfileName.ValueString(), "Test Profile")
	}
	if m.Priority.ValueInt64() != 10 {
		t.Errorf("Priority = %d, want 10", m.Priority.ValueInt64())
	}
	if m.Rev.ValueInt64() != 3 {
		t.Errorf("Rev = %d, want 3", m.Rev.ValueInt64())
	}
	if m.OrganizationId.ValueString() != "org-xyz" {
		t.Errorf("OrganizationId = %q", m.OrganizationId.ValueString())
	}
	if m.SecurePrivate == nil {
		t.Fatal("SecurePrivate is nil")
	}
	if m.SecurePrivate.TrustedNetworksEnabled.ValueBool() != true {
		t.Error("SecurePrivate.TrustedNetworksEnabled should be true")
	}
	if m.SecurePrivate.EnforcementPause == nil {
		t.Fatal("SecurePrivate.EnforcementPause is nil")
	}
	if m.SecurePrivate.EnforcementPause.Enabled.ValueBool() != true {
		t.Error("SecurePrivate enforcement pause should be enabled")
	}
	if m.SecurePrivate.EnforcementPause.DurationMinutes.ValueInt64() != 30 {
		t.Errorf("enforcement pause duration = %d, want 30", m.SecurePrivate.EnforcementPause.DurationMinutes.ValueInt64())
	}
	if m.SecureInternet == nil {
		t.Fatal("SecureInternet is nil")
	}
	if m.SecureInternet.SteeringMode.ValueInt64() != 2 {
		t.Errorf("SteeringMode = %d, want 2", m.SecureInternet.SteeringMode.ValueInt64())
	}
	if m.SecureInternet.TrustedNetworksEnabled.ValueBool() != false {
		t.Error("SecureInternet.TrustedNetworksEnabled should be false")
	}
	if m.UsersData == nil || m.UsersData.AllUsersEnabled.ValueBool() != true {
		t.Error("UsersData.AllUsersEnabled should be true")
	}
	if m.GroupsData == nil || m.GroupsData.AllGroupsEnabled.ValueBool() != false {
		t.Error("GroupsData.AllGroupsEnabled should be false")
	}
}

func TestFlattenZtnaProfile_nilSubstructs(t *testing.T) {
	profile := &ztnaprofiles.ZtnaProfile{
		ProfileId:   ptr("prof-minimal"),
		ProfileName: ptr("Minimal"),
	}

	var m ztnaProfileModel
	flattenZtnaProfile(profile, &m)

	if m.ID.ValueString() != "prof-minimal" {
		t.Errorf("ID = %q", m.ID.ValueString())
	}
	if m.SecurePrivate != nil {
		t.Error("SecurePrivate should be nil when not in response")
	}
	if m.SecureInternet != nil {
		t.Error("SecureInternet should be nil when not in response")
	}
	if m.UsersData != nil {
		t.Error("UsersData should be nil")
	}
	if m.GroupsData != nil {
		t.Error("GroupsData should be nil")
	}
}

func TestFlattenZtnaProfile_priorityPreservesExistingState(t *testing.T) {
	profile := &ztnaprofiles.ZtnaProfile{
		ProfileId: ptr("prof-1"),
		Priority:  ptr(int32(99)),
	}

	m := ztnaProfileModel{
		Priority: types.Int64Value(5),
	}
	flattenZtnaProfile(profile, &m)

	if m.Priority.ValueInt64() != 5 {
		t.Errorf("Priority should preserve state value 5, got %d", m.Priority.ValueInt64())
	}
}

func TestFlattenOSPlatform_nil(t *testing.T) {
	result := flattenOSPlatform(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestFlattenOSPlatform_enabled(t *testing.T) {
	p := &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(true)}
	result := flattenOSPlatform(p)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.Enabled.ValueBool() != true {
		t.Error("expected enabled=true")
	}
}

func TestFlattenOperatingSystems_nil(t *testing.T) {
	result := flattenOperatingSystems(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestFlattenOperatingSystems_full(t *testing.T) {
	p := &ztnaprofiles.ZtnaProfileOSProfilesMetadata{
		MacIntel: &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(true)},
		Win:      &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(true)},
		Linux64:  &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(false)},
		AppleIos: &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(true)},
		Android: &ztnaprofiles.ZtnaProfileAndroidMetadata{
			GenericAndroid: &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(true)},
			KnoxAndroid:    &ztnaprofiles.ZtnaProfileOSPlatformMetadata{Enabled: ptr(false)},
		},
	}

	result := flattenOperatingSystems(p)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.MacIntel == nil || result.MacIntel.Enabled.ValueBool() != true {
		t.Error("MacIntel should be enabled")
	}
	if result.Win == nil || result.Win.Enabled.ValueBool() != true {
		t.Error("Win should be enabled")
	}
	if result.Linux64 == nil || result.Linux64.Enabled.ValueBool() != false {
		t.Error("Linux64 should be disabled")
	}
	if result.AppleIos == nil || result.AppleIos.Enabled.ValueBool() != true {
		t.Error("AppleIos should be enabled")
	}
	if result.Android == nil {
		t.Fatal("Android should not be nil")
	}
	if result.Android.GenericAndroid == nil || result.Android.GenericAndroid.Enabled.ValueBool() != true {
		t.Error("GenericAndroid should be enabled")
	}
	if result.Android.KnoxAndroid == nil || result.Android.KnoxAndroid.Enabled.ValueBool() != false {
		t.Error("KnoxAndroid should be disabled")
	}
}

func TestExpandEnforcementPause_nil(t *testing.T) {
	result := expandEnforcementPause(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandEnforcementPause_values(t *testing.T) {
	m := &ztnaEnforcementPauseModel{
		Enabled:         types.BoolValue(true),
		DurationMinutes: types.Int64Value(45),
	}
	result := expandEnforcementPause(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.Enabled == nil || *result.Enabled != true {
		t.Error("Enabled should be true")
	}
	if result.DurationMinutes == nil || *result.DurationMinutes != 45 {
		t.Errorf("DurationMinutes = %v, want 45", result.DurationMinutes)
	}
}

func TestExpandEnforcementPause_nullFields(t *testing.T) {
	m := &ztnaEnforcementPauseModel{
		Enabled:         types.BoolNull(),
		DurationMinutes: types.Int64Null(),
	}
	result := expandEnforcementPause(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.Enabled != nil {
		t.Error("Enabled should be nil for null input")
	}
	if result.DurationMinutes != nil {
		t.Error("DurationMinutes should be nil for null input")
	}
}

func TestExpandUsersInput_nil(t *testing.T) {
	result := expandUsersInput(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandUsersInput_enabled(t *testing.T) {
	m := &ztnaUsersDataModel{AllUsersEnabled: types.BoolValue(true)}
	result := expandUsersInput(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.AllUsersEnabled == nil || *result.AllUsersEnabled != true {
		t.Error("AllUsersEnabled should be true")
	}
}

func TestExpandGroupsInput_nil(t *testing.T) {
	result := expandGroupsInput(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandGroupsInput_disabled(t *testing.T) {
	m := &ztnaGroupsDataModel{AllGroupsEnabled: types.BoolValue(false)}
	result := expandGroupsInput(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.AllGroupsEnabled == nil || *result.AllGroupsEnabled != false {
		t.Error("AllGroupsEnabled should be false")
	}
}

func TestExpandOSPlatform_nil(t *testing.T) {
	result := expandOSPlatform(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandOSPlatform_enabled(t *testing.T) {
	m := &ztnaOSPlatformModel{Enabled: types.BoolValue(true)}
	result := expandOSPlatform(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.Enabled == nil || *result.Enabled != true {
		t.Error("expected enabled=true")
	}
}

func TestExpandOperatingSystemsInput_nil(t *testing.T) {
	result := expandOperatingSystemsInput(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandOperatingSystemsInput_full(t *testing.T) {
	m := &ztnaOperatingSystemsModel{
		MacIntel: &ztnaOSPlatformModel{Enabled: types.BoolValue(true)},
		Win:      &ztnaOSPlatformModel{Enabled: types.BoolValue(true)},
		Linux64:  &ztnaOSPlatformModel{Enabled: types.BoolValue(false)},
		AppleIos: &ztnaOSPlatformModel{Enabled: types.BoolValue(true)},
		Android: &ztnaAndroidModel{
			GenericAndroid: &ztnaOSPlatformModel{Enabled: types.BoolValue(true)},
			KnoxAndroid:    &ztnaOSPlatformModel{Enabled: types.BoolValue(false)},
		},
	}

	result := expandOperatingSystemsInput(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.MacIntel == nil || result.MacIntel.Enabled == nil || *result.MacIntel.Enabled != true {
		t.Error("MacIntel should be enabled")
	}
	if result.Win == nil || *result.Win.Enabled != true {
		t.Error("Win should be enabled")
	}
	if result.Linux64 == nil || *result.Linux64.Enabled != false {
		t.Error("Linux64 should be disabled")
	}
	if result.AppleIos == nil || *result.AppleIos.Enabled != true {
		t.Error("AppleIos should be enabled")
	}
	if result.Android == nil {
		t.Fatal("Android should not be nil")
	}
	if result.Android.GenericAndroid == nil || *result.Android.GenericAndroid.Enabled != true {
		t.Error("GenericAndroid should be enabled")
	}
	if result.Android.KnoxAndroid == nil || *result.Android.KnoxAndroid.Enabled != false {
		t.Error("KnoxAndroid should be disabled")
	}
}

func TestExpandInternetAccessInput_nil(t *testing.T) {
	result := expandInternetAccessInput(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandInternetAccessInput_values(t *testing.T) {
	m := &ztnaInternetAccessModel{
		SteeringMode:           types.Int64Value(1),
		TrustedNetworksEnabled: types.BoolValue(true),
		EnforcementPause: &ztnaEnforcementPauseModel{
			Enabled:         types.BoolValue(false),
			DurationMinutes: types.Int64Value(15),
		},
	}

	result := expandInternetAccessInput(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.SteeringMode == nil || *result.SteeringMode != 1 {
		t.Errorf("SteeringMode = %v, want 1", result.SteeringMode)
	}
	if result.TrustedNetworksEnabled == nil || *result.TrustedNetworksEnabled != true {
		t.Error("TrustedNetworksEnabled should be true")
	}
	if result.EnforcementPause == nil {
		t.Fatal("EnforcementPause should not be nil")
	}
	if *result.EnforcementPause.Enabled != false {
		t.Error("enforcement pause should be disabled")
	}
}

func TestExpandPrivateAccessInput_nil(t *testing.T) {
	result := expandPrivateAccessInput(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestExpandPrivateAccessInput_withTrustedNetworks(t *testing.T) {
	m := &ztnaPrivateAccessModel{
		TrustedNetworksEnabled: types.BoolValue(true),
		DnsSteeringDestIds:     types.ListNull(types.StringType),
	}

	result := expandPrivateAccessInput(m)
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.TrustedNetworksEnabled == nil || *result.TrustedNetworksEnabled != true {
		t.Error("TrustedNetworksEnabled should be true")
	}
}
