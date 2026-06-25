// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestValidateAndResolveConfig_envVarsOnly(t *testing.T) {
	t.Setenv("CISCOSECUREACCESS_KEY_ID", "env-id")
	t.Setenv("CISCOSECUREACCESS_KEY_SECRET", "env-secret")

	config := ciscosecureaccessProviderModel{
		KeyID:       types.StringNull(),
		KeySecret:   types.StringNull(),
		APIEndpoint: types.StringNull(),
	}

	keyID, keySecret, apiEndpoint := validateAndResolveConfig(context.Background(), config)

	if keyID != "env-id" {
		t.Errorf("keyID = %q, want %q", keyID, "env-id")
	}
	if keySecret != "env-secret" {
		t.Errorf("keySecret = %q, want %q", keySecret, "env-secret")
	}
	if apiEndpoint != "" {
		t.Errorf("apiEndpoint = %q, want empty", apiEndpoint)
	}
}

func TestValidateAndResolveConfig_configOverridesEnv(t *testing.T) {
	t.Setenv("CISCOSECUREACCESS_KEY_ID", "env-id")
	t.Setenv("CISCOSECUREACCESS_KEY_SECRET", "env-secret")

	config := ciscosecureaccessProviderModel{
		KeyID:       types.StringValue("config-id"),
		KeySecret:   types.StringValue("config-secret"),
		APIEndpoint: types.StringValue("https://custom.api.example.com"),
	}

	keyID, keySecret, apiEndpoint := validateAndResolveConfig(context.Background(), config)

	if keyID != "config-id" {
		t.Errorf("keyID = %q, want %q", keyID, "config-id")
	}
	if keySecret != "config-secret" {
		t.Errorf("keySecret = %q, want %q", keySecret, "config-secret")
	}
	if apiEndpoint != "https://custom.api.example.com" {
		t.Errorf("apiEndpoint = %q, want %q", apiEndpoint, "https://custom.api.example.com")
	}
}

func TestValidateAndResolveConfig_emptyConfigFallsBackToEnv(t *testing.T) {
	t.Setenv("CISCOSECUREACCESS_KEY_ID", "env-id")
	t.Setenv("CISCOSECUREACCESS_KEY_SECRET", "env-secret")

	config := ciscosecureaccessProviderModel{
		KeyID:       types.StringValue(""),
		KeySecret:   types.StringValue(""),
		APIEndpoint: types.StringNull(),
	}

	keyID, keySecret, _ := validateAndResolveConfig(context.Background(), config)

	if keyID != "env-id" {
		t.Errorf("keyID = %q, want %q (empty config should not override env)", keyID, "env-id")
	}
	if keySecret != "env-secret" {
		t.Errorf("keySecret = %q, want %q (empty config should not override env)", keySecret, "env-secret")
	}
}

func TestValidateAndResolveConfig_noEnvNoConfig(t *testing.T) {
	os.Unsetenv("CISCOSECUREACCESS_KEY_ID")
	os.Unsetenv("CISCOSECUREACCESS_KEY_SECRET")

	config := ciscosecureaccessProviderModel{
		KeyID:       types.StringNull(),
		KeySecret:   types.StringNull(),
		APIEndpoint: types.StringNull(),
	}

	keyID, keySecret, apiEndpoint := validateAndResolveConfig(context.Background(), config)

	if keyID != "" {
		t.Errorf("keyID = %q, want empty", keyID)
	}
	if keySecret != "" {
		t.Errorf("keySecret = %q, want empty", keySecret)
	}
	if apiEndpoint != "" {
		t.Errorf("apiEndpoint = %q, want empty", apiEndpoint)
	}
}
