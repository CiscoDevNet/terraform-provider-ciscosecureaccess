// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for private resource tests
const (
	// Test configuration constants
	testPrivateResourceNamePrefix  = "tfAcc"
	testPrivateResourceFixedName   = "TFP Network Test Resource"
	testPrivateResourceAddress     = "10.10.110.2/32"
	testPrivateResourceClientAddr  = "10.10.110.2"
	testPrivateResourceDesc        = "Application used for performing tests"
	testPrivateResourceUpdatedDesc = "Updated application used for performing tests"

	// Test port and protocol constants
	testPrivateResourcePortHTTPS  = "443"
	testPrivateResourcePortUDP    = "5443"
	testPrivateResourcePortSSH    = "22"
	testPrivateResourcePortRDP    = "3389"
	testPrivateResourceProtoHTTPS = "http/https"
	testPrivateResourceProtoUDP   = "udp"
	testPrivateResourceProtoSSH   = "ssh"
	testPrivateResourceProtoRDP   = "rdp-tcp"

	// Access type constants
	testAccessTypeNetwork = "network"
	testAccessTypeClient  = "client"
	testAccessTypeBrowser = "browser"

	// Browser access constants
	testPrivateResourceBrowserPrefix = "tf-browser-jira"
	testPrivateResourceBrowserSNI    = "jira.internal.example.com"

	// Resource identifiers
	testPrivateResourceName = "ciscosecureaccess_private_resource.test_resource"
)

func TestPrivateResourceResource_browserRequestDefaults(t *testing.T) {
	ctx := context.Background()
	plan := testPrivateResourceBrowserPlan(t, []string{testAccessTypeBrowser}, testPrivateResourcePortHTTPS)

	req, diags := formatCreatePrivateResourceRequest(ctx, &plan)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(req.AccessTypes) != 1 {
		t.Fatalf("expected 1 access type, got %d", len(req.AccessTypes))
	}

	browserAccess := req.AccessTypes[0].BrowserBasedAccessRequest
	if browserAccess == nil {
		if payload, err := json.Marshal(req.AccessTypes[0]); err == nil {
			tflog.Debug(ctx, "unexpected access type payload", map[string]interface{}{
				"payload": string(payload),
			})
		}
		t.Fatal("expected browser access request")
	}
	if browserAccess.Type != testAccessTypeBrowser {
		t.Fatalf("expected browser type %q, got %q", testAccessTypeBrowser, browserAccess.Type)
	}
	if string(browserAccess.Protocol) != browserProtocolHTTPS {
		t.Fatalf("expected browser protocol %q, got %q", browserProtocolHTTPS, browserAccess.Protocol)
	}
	if browserAccess.ExternalFQDNPrefix == nil || *browserAccess.ExternalFQDNPrefix != testPrivateResourceBrowserPrefix {
		t.Fatalf("expected external FQDN prefix %q, got %#v", testPrivateResourceBrowserPrefix, browserAccess.ExternalFQDNPrefix)
	}
	if browserAccess.SslVerificationEnabled == nil || !*browserAccess.SslVerificationEnabled {
		t.Fatalf("expected SSL verification to default to true, got %#v", browserAccess.SslVerificationEnabled)
	}
}

func TestPrivateResourceResource_browserPlanModifierDefaults(t *testing.T) {
	ctx := context.Background()
	model := testPrivateResourceBrowserPlan(t, []string{testAccessTypeBrowser}, testPrivateResourcePortHTTPS)

	var schemaResp fwresource.SchemaResponse
	(&privateResourceResource{}).Schema(ctx, fwresource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics)
	}

	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := plan.Set(ctx, &model)
	if diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}

	var protocolResp planmodifier.StringResponse
	browserProtocolDefaultModifier{}.PlanModifyString(ctx, planmodifier.StringRequest{
		ConfigValue: types.StringNull(),
		Plan:        plan,
	}, &protocolResp)
	if protocolResp.Diagnostics.HasError() {
		t.Fatalf("unexpected protocol diagnostics: %v", protocolResp.Diagnostics)
	}
	if protocolResp.PlanValue.ValueString() != browserProtocolHTTPS {
		t.Fatalf("expected browser_protocol default %q, got %q", browserProtocolHTTPS, protocolResp.PlanValue.ValueString())
	}

	var sslResp planmodifier.BoolResponse
	browserSSLVerificationDefaultModifier{}.PlanModifyBool(ctx, planmodifier.BoolRequest{
		ConfigValue: types.BoolNull(),
		Plan:        plan,
	}, &sslResp)
	if sslResp.Diagnostics.HasError() {
		t.Fatalf("unexpected SSL verification diagnostics: %v", sslResp.Diagnostics)
	}
	if !sslResp.PlanValue.ValueBool() {
		t.Fatalf("expected browser_ssl_verification_enabled to default to true")
	}
}

func TestPrivateResourceResource_browserAccessCanCombineWithClientAndNetwork(t *testing.T) {
	ctx := context.Background()
	plan := testPrivateResourceBrowserPlan(t, []string{testAccessTypeBrowser, testAccessTypeClient, testAccessTypeNetwork}, testPrivateResourcePortHTTPS)

	req, diags := formatCreatePrivateResourceRequest(ctx, &plan)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	var hasBrowser, hasClient, hasNetwork bool
	for _, access := range req.AccessTypes {
		hasBrowser = hasBrowser || access.BrowserBasedAccessRequest != nil
		hasClient = hasClient || access.ClientBasedAccess != nil
		hasNetwork = hasNetwork || access.NetworkBasedAccess != nil
	}

	if !hasBrowser || !hasClient || !hasNetwork {
		t.Fatalf("expected browser, client, and network access types; got browser=%t client=%t network=%t", hasBrowser, hasClient, hasNetwork)
	}
}

func TestPrivateResourceResource_browserValidationRequiresPrefix(t *testing.T) {
	ctx := context.Background()
	plan := testPrivateResourceBrowserPlan(t, []string{testAccessTypeBrowser}, testPrivateResourcePortHTTPS)
	plan.BrowserExternalFQDNPrefix = types.StringNull()

	diags := validatePrivateResourcePlan(ctx, &plan)
	if !diags.HasError() {
		t.Fatal("expected diagnostics for missing browser_external_fqdn_prefix")
	}
}

func TestPrivateResourceResource_browserValidationAllowsHTTPAndHTTPSPorts(t *testing.T) {
	ctx := context.Background()
	plan := testPrivateResourceBrowserPlan(t, []string{testAccessTypeBrowser}, "80, 443")

	diags := validatePrivateResourcePlan(ctx, &plan)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics for supported browser access ports: %v", diags)
	}
}

func TestPrivateResourceResource_browserValidationRejectsUnsupportedPorts(t *testing.T) {
	ctx := context.Background()
	plan := testPrivateResourceBrowserPlan(t, []string{testAccessTypeBrowser}, "8443")

	diags := validatePrivateResourcePlan(ctx, &plan)
	if !diags.HasError() {
		t.Fatal("expected diagnostics for unsupported browser access port")
	}
}

func TestPrivateResourceResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := generateTestResourceName()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckPrivateResourceDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceConfig(rName, testAccessTypeNetwork),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildNetworkAccessStateChecks(rName),
				},
			},
		})
	}, minWaitTime)
}

func TestPrivateResourceResource_ztna(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := generateTestResourceName()

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckPrivateResourceDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceConfig(rName, testAccessTypeClient),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildClientAccessStateChecks(rName),
				},
			},
		})
	}, minWaitTime)
}

func TestPrivateResourceResource_networkReportedConfig(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := fmt.Sprintf("%s-%s", testPrivateResourceFixedName, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
				},
				{
					Config:            testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortSSH, testPrivateResourceProtoSSH),
				},
			},
		})
	}, minWaitTime)
}

func TestPrivateResourceResource_networkReportedConfigRDP(t *testing.T) {
	rateLimitedTest(t, func() {
		rName := fmt.Sprintf("%s-rdp-%s", testPrivateResourceFixedName, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
						resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
						resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
					),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
				},
				{
					Config:            testAccPrivateResourceReportedConfig(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
					ConfigStateChecks: buildNetworkAccessStateChecksWithSelectors(rName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortRDP, testPrivateResourceProtoRDP),
				},
			},
		})
	}, minWaitTime)
}

func TestPrivateResourceResource_accessTypeCombinationsCRUD(t *testing.T) {
	accessTypeCombinations := [][]string{
		{testAccessTypeNetwork},
		{testAccessTypeClient},
		{testAccessTypeBrowser},
		{testAccessTypeNetwork, testAccessTypeClient},
		{testAccessTypeNetwork, testAccessTypeBrowser},
		{testAccessTypeClient, testAccessTypeBrowser},
		{testAccessTypeNetwork, testAccessTypeClient, testAccessTypeBrowser},
	}

	for _, accessTypes := range accessTypeCombinations {
		accessTypes := accessTypes
		t.Run(strings.Join(accessTypes, "_"), func(t *testing.T) {
			rateLimitedTest(t, func() {
				rName := generateTestResourceName()
				browserPrefix := fmt.Sprintf("tf-%s", strings.ToLower(acctest.RandStringFromCharSet(12, acctest.CharSetAlphaNum)))

				resource.Test(t, resource.TestCase{
					PreCheck:                 func() { testAccPreCheck(t) },
					ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
					CheckDestroy:             testAccCheckPrivateResourceDestroy,
					Steps: []resource.TestStep{
						{
							Config: testAccPrivateResourceCombinationConfig(rName, accessTypes, browserPrefix, testPrivateResourceDesc),
							Check: resource.ComposeAggregateTestCheckFunc(
								resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
								resource.TestCheckResourceAttr(testPrivateResourceName, "name", rName),
								resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceDesc),
							),
							ConfigStateChecks: buildCombinationAccessStateChecks(rName, accessTypes, testPrivateResourceDesc),
						},
						{
							Config: testAccPrivateResourceCombinationConfig(rName, accessTypes, browserPrefix, testPrivateResourceUpdatedDesc),
							Check: resource.ComposeAggregateTestCheckFunc(
								resource.TestCheckResourceAttrSet(testPrivateResourceName, "id"),
								resource.TestCheckResourceAttr(testPrivateResourceName, "description", testPrivateResourceUpdatedDesc),
							),
							ConfigStateChecks: buildCombinationAccessStateChecks(rName, accessTypes, testPrivateResourceUpdatedDesc),
						},
						{
							Config:   testAccPrivateResourceCombinationConfig(rName, accessTypes, browserPrefix, testPrivateResourceUpdatedDesc),
							PlanOnly: true,
						},
					},
				})
			}, minWaitTime)
		})
	}
}

// generateTestResourceName creates a unique test resource name
func generateTestResourceName() string {
	return fmt.Sprintf("%s%s", testPrivateResourceNamePrefix, acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
}

func testPrivateResourceBrowserPlan(t *testing.T, accessTypes []string, ports string) privateResourceResourceModel {
	t.Helper()
	ctx := context.Background()

	accessTypesSet, diags := types.SetValueFrom(ctx, types.StringType, accessTypes)
	if diags.HasError() {
		t.Fatalf("failed to build access types set: %v", diags)
	}
	clientAddressesSet, diags := types.SetValueFrom(ctx, types.StringType, []string{testPrivateResourceClientAddr})
	if diags.HasError() {
		t.Fatalf("failed to build client addresses set: %v", diags)
	}
	addressesSet, diags := types.SetValueFrom(ctx, types.StringType, []string{testPrivateResourceClientAddr})
	if diags.HasError() {
		t.Fatalf("failed to build addresses set: %v", diags)
	}
	trafficSelectorSet, diags := types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: trafficSelectorModel{}.AttrTypes()},
		[]trafficSelectorModel{{
			Ports:    types.StringValue(ports),
			Protocol: types.StringValue(testPrivateResourceProtoHTTPS),
		}},
	)
	if diags.HasError() {
		t.Fatalf("failed to build traffic selector set: %v", diags)
	}
	resourceAddressesSet, diags := types.SetValueFrom(
		ctx,
		types.ObjectType{AttrTypes: addressTypesModel{}.AttrTypes()},
		[]addressTypesModel{{
			Addresses:       addressesSet,
			TrafficSelector: trafficSelectorSet,
		}},
	)
	if diags.HasError() {
		t.Fatalf("failed to build resource addresses set: %v", diags)
	}

	return privateResourceResourceModel{
		Name:                          types.StringValue(testPrivateResourceFixedName),
		AccessTypes:                   accessTypesSet,
		Addresses:                     resourceAddressesSet,
		Description:                   types.StringValue(testPrivateResourceDesc),
		ClientReachableAddresses:      clientAddressesSet,
		CertificateID:                 types.Int64Null(),
		BrowserProtocol:               types.StringNull(),
		BrowserExternalFQDNPrefix:     types.StringValue(testPrivateResourceBrowserPrefix),
		BrowserSNI:                    types.StringValue(testPrivateResourceBrowserSNI),
		BrowserSSLVerificationEnabled: types.BoolNull(),
		BrowserExternalFQDN:           types.StringNull(),
	}
}

// buildNetworkAccessStateChecks returns state checks for network access type
func buildNetworkAccessStateChecks(resourceName string) []statecheck.StateCheck {
	return buildNetworkAccessStateChecksWithSelectors(resourceName, testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS, testPrivateResourcePortUDP, testPrivateResourceProtoUDP)
}

func buildNetworkAccessStateChecksWithSelectors(resourceName, firstPort, firstProtocol, secondPort, secondProtocol string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("addresses"),
			knownvalue.SetExact([]knownvalue.Check{
				knownvalue.ObjectExact(map[string]knownvalue.Check{
					"addresses": knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceAddress)}),
					"traffic_selector": knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"ports":    knownvalue.StringExact(firstPort),
							"protocol": knownvalue.StringExact(firstProtocol),
						}),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"ports":    knownvalue.StringExact(secondPort),
							"protocol": knownvalue.StringExact(secondProtocol),
						}),
					}),
				}),
			})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"),
			knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testAccessTypeNetwork)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("description"),
			knownvalue.StringExact(testPrivateResourceDesc)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("name"),
			knownvalue.StringExact(resourceName)),
	}
}

// buildClientAccessStateChecks returns state checks for client access type
func buildClientAccessStateChecks(resourceName string) []statecheck.StateCheck {
	checks := buildNetworkAccessStateChecks(resourceName)

	// Add client-specific checks
	clientChecks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("client_reachable_addresses"),
			knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceClientAddr)})),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"),
			knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testAccessTypeClient)})),
	}

	return append(checks[:1], append(clientChecks, checks[2:]...)...)
}

func buildCombinationAccessStateChecks(resourceName string, accessTypes []string, description string) []statecheck.StateCheck {
	accessTypeChecks := make([]knownvalue.Check, 0, len(accessTypes))
	for _, accessType := range accessTypes {
		accessTypeChecks = append(accessTypeChecks, knownvalue.StringExact(accessType))
	}

	checks := []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("access_types"), knownvalue.SetExact(accessTypeChecks)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("description"), knownvalue.StringExact(description)),
		statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("name"), knownvalue.StringExact(resourceName)),
	}

	if containsAccessType(accessTypes, testAccessTypeClient) {
		checks = append(checks,
			statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("client_reachable_addresses"),
				knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testPrivateResourceClientAddr)})),
		)
	}

	if containsAccessType(accessTypes, testAccessTypeBrowser) {
		checks = append(checks,
			statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("browser_protocol"), knownvalue.StringExact(browserProtocolHTTPS)),
			statecheck.ExpectKnownValue(testPrivateResourceName, tfjsonpath.New("browser_ssl_verification_enabled"), knownvalue.Bool(true)),
		)
	}

	return checks
}

func containsAccessType(accessTypes []string, accessType string) bool {
	for _, candidate := range accessTypes {
		if candidate == accessType {
			return true
		}
	}

	return false
}

func accessTypesAsHCL(accessTypes []string) string {
	quotedAccessTypes := make([]string, 0, len(accessTypes))
	for _, accessType := range accessTypes {
		quotedAccessTypes = append(quotedAccessTypes, fmt.Sprintf("%q", accessType))
	}

	return strings.Join(quotedAccessTypes, ", ")
}

// testAccPrivateResourceConfig generates Terraform configuration for private resource tests
func testAccPrivateResourceConfig(name, accessType string) string {
	var clientAddresses string
	if accessType == testAccessTypeClient {
		clientAddresses = fmt.Sprintf(`client_reachable_addresses = ["%s"]`, testPrivateResourceClientAddr)
	}

	return fmt.Sprintf(`
resource "ciscosecureaccess_private_resource" "test_resource" {
  name         = "%s"
  access_types = ["%s"]
  description  = "%s"
  %s
  addresses = [{
    addresses = ["%s"]
    traffic_selector = [
      { ports = "%s", protocol = "%s" },
      { ports = "%s", protocol = "%s" }
    ]
  }]
}`, name, accessType, testPrivateResourceDesc, clientAddresses,
		testPrivateResourceAddress,
		testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS,
		testPrivateResourcePortUDP, testPrivateResourceProtoUDP)
}

func testAccPrivateResourceCombinationConfig(name string, accessTypes []string, browserPrefix string, description string) string {
	var clientAddresses string
	if containsAccessType(accessTypes, testAccessTypeClient) {
		clientAddresses = fmt.Sprintf(`client_reachable_addresses = ["%s"]`, testPrivateResourceClientAddr)
	}

	var browserFields string
	if containsAccessType(accessTypes, testAccessTypeBrowser) {
		browserFields = fmt.Sprintf(`browser_external_fqdn_prefix = "%s"`, browserPrefix)
	}

	return fmt.Sprintf(`
resource "ciscosecureaccess_private_resource" "test_resource" {
  name         = "%s"
  access_types = [%s]
  description  = "%s"
  %s
  %s
  addresses = [{
    addresses = ["%s"]
    traffic_selector = [
      { ports = "%s", protocol = "%s" }
    ]
  }]
}`, name, accessTypesAsHCL(accessTypes), description, clientAddresses, browserFields,
		testPrivateResourceAddress,
		testPrivateResourcePortHTTPS, testPrivateResourceProtoHTTPS)
}

func testAccPrivateResourceReportedConfig(name, firstPort, firstProtocol, secondPort, secondProtocol string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_private_resource" "test_resource" {
  name         = "%s"
  access_types = ["%s"]
  description  = "%s"
  addresses = [{
    addresses = ["%s"]
    traffic_selector = [
      { ports = "%s", protocol = "%s" },
      { ports = "%s", protocol = "%s" }
    ]
  }]
}`,
		name,
		testAccessTypeNetwork,
		testPrivateResourceDesc,
		testPrivateResourceAddress,
		firstPort,
		firstProtocol,
		secondPort,
		secondProtocol,
	)
}

func testAccCheckPrivateResourceDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetPrivateAppsClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_private_resource" {
			continue
		}
		id, err := strconv.ParseInt(rs.Primary.ID, 10, 64)
		if err != nil {
			continue
		}
		_, httpRes, _ := c.PrivateResourcesAPI.GetPrivateResource(ctx, id).Execute()
		if httpRes == nil || httpRes.StatusCode != 404 {
			return fmt.Errorf("private resource %d still exists after destroy", id)
		}
	}
	return nil
}
