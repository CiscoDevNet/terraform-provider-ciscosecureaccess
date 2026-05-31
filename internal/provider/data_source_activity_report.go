// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Ensure the implementation satisfies the expected interfaces.
var _ datasource.DataSource = &activityReportDataSource{}

// NewActivityReportDataSource is a helper function to simplify the provider implementation.
func NewActivityReportDataSource() datasource.DataSource {
	return &activityReportDataSource{}
}

// activityReportDataSource is the data source implementation.
type activityReportDataSource struct {
	client reports.APIClient
}

// activityReportDataSourceModel maps the data source schema data.
type activityReportDataSourceModel struct {
	From        types.String `tfsdk:"from"`
	To          types.String `tfsdk:"to"`
	Limit       types.Int64  `tfsdk:"limit"`
	Offset      types.Int64  `tfsdk:"offset"`
	Domains     types.String `tfsdk:"domains"`
	Verdict     types.String `tfsdk:"verdict"`
	IdentityIDs types.String `tfsdk:"identityids"`
	TotalCount  types.Int64  `tfsdk:"total_count"`
	Data        types.String `tfsdk:"data"`
}

// Metadata returns the data source type name.
func (d *activityReportDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_activity_report"
}

// Configure adds the provider configured client to the data source.
func (d *activityReportDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *client.SSEClientFactory, got: %T", req.ProviderData))
		return
	}
	reportsClient := factory.GetReportsClient(ctx)
	cfg := reportsClient.GetConfig()
	cfg.Servers[0].URL = "https://api.umbrella.com"

	sseAuthConfig := &clientcredentials.Config{
		ClientID:     factory.KeyId,
		ClientSecret: factory.KeySecret,
		TokenURL:     "https://api.sse.cisco.com/auth/v2/token",
	}
	baseTransport := oauth2.NewClient(ctx, sseAuthConfig.TokenSource(ctx)).Transport
	cfg.HTTPClient = &http.Client{
		Transport: &reportsPathRewriteTransport{base: baseTransport},
	}

	d.client = *reportsClient
}

type reportsPathRewriteTransport struct {
	base http.RoundTripper
}

func (t *reportsPathRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Path = strings.Replace(cloned.URL.Path, "/reports/v2/", "/reports.us/v2/", 1)
	cloned.URL.RawPath = strings.Replace(cloned.URL.RawPath, "/reports/v2/", "/reports.us/v2/", 1)
	return t.base.RoundTrip(cloned)
}

func (d *activityReportDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Data source for retrieving Cisco Secure Access activity report data",
		MarkdownDescription: "Data source for retrieving Cisco Secure Access activity report data",
		Attributes: map[string]schema.Attribute{
			"from": schema.StringAttribute{
				Description:         "Start time for the activity report, as a timestamp or relative time string.",
				MarkdownDescription: "Start time for the activity report, as a timestamp or relative time string.",
				Optional:            true,
			},
			"to": schema.StringAttribute{
				Description:         "End time for the activity report, as a timestamp or relative time string.",
				MarkdownDescription: "End time for the activity report, as a timestamp or relative time string.",
				Optional:            true,
			},
			"limit": schema.Int64Attribute{
				Description:         "Maximum number of activity records to return.",
				MarkdownDescription: "Maximum number of activity records to return.",
				Optional:            true,
			},
			"offset": schema.Int64Attribute{
				Description:         "Index offset for the activity report collection.",
				MarkdownDescription: "Index offset for the activity report collection.",
				Optional:            true,
			},
			"domains": schema.StringAttribute{
				Description:         "Domain name or comma-delimited list of domain names to filter activity records.",
				MarkdownDescription: "Domain name or comma-delimited list of domain names to filter activity records.",
				Optional:            true,
			},
			"verdict": schema.StringAttribute{
				Description:         "Verdict string or comma-delimited list of verdict strings to filter activity records.",
				MarkdownDescription: "Verdict string or comma-delimited list of verdict strings to filter activity records.",
				Optional:            true,
			},
			"identityids": schema.StringAttribute{
				Description:         "Identity ID or comma-delimited list of identity IDs to filter activity records.",
				MarkdownDescription: "Identity ID or comma-delimited list of identity IDs to filter activity records.",
				Optional:            true,
			},
			"total_count": schema.Int64Attribute{
				Description:         "Total number of activity records returned by the report query.",
				MarkdownDescription: "Total number of activity records returned by the report query.",
				Computed:            true,
			},
			"data": schema.StringAttribute{
				Description:         "JSON-encoded list of activity records returned by the report query.",
				MarkdownDescription: "JSON-encoded list of activity records returned by the report query.",
				Computed:            true,
			},
		},
	}
}

// Read retrieves the activity report from the API and sets the state.
func (d *activityReportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data activityReportDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading activity report", map[string]interface{}{
		"from":        data.From.ValueString(),
		"to":          data.To.ValueString(),
		"limit":       data.Limit.ValueInt64(),
		"offset":      data.Offset.ValueInt64(),
		"domains":     data.Domains.ValueString(),
		"verdict":     data.Verdict.ValueString(),
		"identityids": data.IdentityIDs.ValueString(),
	})

	activityReq := d.client.ActivityAPI.GetActivities(ctx)
	if !data.From.IsNull() {
		activityReq = activityReq.From(data.From.ValueString())
	}
	if !data.To.IsNull() {
		activityReq = activityReq.To(data.To.ValueString())
	}
	if !data.Limit.IsNull() {
		activityReq = activityReq.Limit(data.Limit.ValueInt64())
	}
	if !data.Offset.IsNull() {
		activityReq = activityReq.Offset(data.Offset.ValueInt64())
	}
	if !data.Domains.IsNull() {
		activityReq = activityReq.Domains(data.Domains.ValueString())
	}
	if !data.Verdict.IsNull() {
		activityReq = activityReq.Verdict(data.Verdict.ValueString())
	}
	if !data.IdentityIDs.IsNull() {
		activityReq = activityReq.Identityids(data.IdentityIDs.ValueString())
	}

	activityResp, httpRes, err := activityReq.Execute()
	if err != nil {
		var httpRespDetails string
		if httpRes != nil {
			httpRespDetails = fmt.Sprintf("HTTP response status: %d", httpRes.StatusCode)
		} else {
			httpRespDetails = "HTTP response: <nil>"
		}

		resp.Diagnostics.AddError(
			"Error retrieving activity report",
			fmt.Sprintf("Could not retrieve activity report: %s\n%v", err.Error(), httpRespDetails),
		)
		return
	}

	activityData, err := json.Marshal(activityResp.Data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error encoding activity report data",
			fmt.Sprintf("Could not encode activity report data as JSON: %s", err.Error()),
		)
		return
	}

	data.TotalCount = types.Int64Value(int64(len(activityResp.Data)))
	data.Data = types.StringValue(string(activityData))

	tflog.Info(ctx, "Successfully retrieved activity report", map[string]interface{}{
		"totalCount": data.TotalCount.ValueInt64(),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
