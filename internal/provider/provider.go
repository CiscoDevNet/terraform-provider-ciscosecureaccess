package provider

import (
	"context"
	"os"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Environment variable names
const (
	envKeyID     = "CISCOSECUREACCESS_KEY_ID"
	envKeySecret = "CISCOSECUREACCESS_KEY_SECRET"
)

var (
	_ provider.Provider = &ciscosecureaccessProvider{}
)

type ciscosecureaccessProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version       string
	clientFactory *client.SSEClientFactory
}

type ciscosecureaccessProviderModel struct {
	APIEndpoint types.String `tfsdk:"api_endpoint"`
	KeyID       types.String `tfsdk:"key_id"`
	KeySecret   types.String `tfsdk:"key_secret"`
}

// New creates a new Cisco Secure Access provider instance
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ciscosecureaccessProvider{
			version: version,
		}
	}
}

// Metadata returns the provider type name.
func (p *ciscosecureaccessProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ciscosecureaccess"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *ciscosecureaccessProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform Provider for Cisco Secure Access",
		Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{
				Description: "Cisco Secure Access API Key ID. Can also be set via the " + envKeyID + " environment variable.",
				Optional:    true,
			},
			"key_secret": schema.StringAttribute{
				Description: "Cisco Secure Access API Key Secret. Can also be set via the " + envKeySecret + " environment variable.",
				Optional:    true,
				Sensitive:   true,
			},
			"api_endpoint": schema.StringAttribute{
				Description: "Cisco Secure Access API endpoint. Optional custom endpoint for the API.",
				Optional:    true,
			},
		},
	}
}

func (p *ciscosecureaccessProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring Cisco Secure Access client")

	// Retrieve provider data from configuration
	var config ciscosecureaccessProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.
	if config.KeyID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("key_id"),
			"Unknown Cisco Secure Access API Key ID",
			"The provider cannot create the Cisco Secure Access API client as there is an unknown configuration value for the API Key ID.",
		)
	}

	if config.KeySecret.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("key_secret"),
			"Unknown Cisco Secure Access API Key Secret",
			"The provider cannot create the Cisco Secure Access API client as there is an unknown configuration value for the API Key Secret.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve configuration values
	keyID, keySecret, apiEndpoint := validateAndResolveConfig(ctx, config)

	// Validate required configuration
	if keyID == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("key_id"),
			"Missing Cisco Secure Access API Key ID",
			"The provider cannot create the Cisco Secure Access API client as there is a missing or empty value for the API Key ID. "+
				"Set the key_id value in the provider configuration or use the "+envKeyID+" environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if keySecret == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("key_secret"),
			"Missing Cisco Secure Access API Key Secret",
			"The provider cannot create the Cisco Secure Access API client as there is a missing or empty value for the API Key Secret. "+
				"Set the key_secret value in the provider configuration or use the "+envKeySecret+" environment variable. "+
				"If either is already set, ensure the value is not empty.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Set up logging context with secure field masking
	ctx = tflog.SetField(ctx, "ciscosecureaccess_key_id", keyID)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "ciscosecureaccess_key_secret")

	tflog.Debug(ctx, "Creating Cisco Secure Access client")

	// Initialize client factory
	p.clientFactory = &client.SSEClientFactory{
		KeyId:       keyID,
		KeySecret:   keySecret,
		ApiEndpoint: apiEndpoint,
	}

	// Make the client factory available during DataSource and Resource
	// type Configure methods.
	resp.DataSourceData = p.clientFactory
	resp.ResourceData = p.clientFactory

	tflog.Info(ctx, "Configured Cisco Secure Access client", map[string]any{"success": true})
}

// validateAndResolveConfig validates the provider configuration and resolves the final values
func validateAndResolveConfig(ctx context.Context, config ciscosecureaccessProviderModel) (keyID, keySecret, apiEndpoint string) {
	// Start with environment variables as defaults
	keyID = os.Getenv(envKeyID)
	keySecret = os.Getenv(envKeySecret)
	apiEndpoint = config.APIEndpoint.ValueString()

	// Override with Terraform configuration if provided
	if !config.KeyID.IsNull() && config.KeyID.ValueString() != "" {
		keyID = config.KeyID.ValueString()
	}

	if !config.KeySecret.IsNull() && config.KeySecret.ValueString() != "" {
		keySecret = config.KeySecret.ValueString()
	}

	return keyID, keySecret, apiEndpoint
}

// DataSources defines the data sources implemented in the provider.
func (p *ciscosecureaccessProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewResourceConnectorGroupsDataSource,
		NewIdentityDataSource,
		NewGroupDataSource,
	}
}

// Resources defines the resources implemented in the provider.
func (p *ciscosecureaccessProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAccessPolicyResource,
		NewDestinationListResource,
		NewNetworkTunnelGroupResource,
		NewGlobalSettingsResource,
		NewPrivateResourceResource,
		NewResourceConnectorAgentResource,
	}
}
