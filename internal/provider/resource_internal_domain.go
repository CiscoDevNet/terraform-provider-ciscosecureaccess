// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/internaldomains"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &internalDomainResource{}
	_ resource.ResourceWithConfigure = &internalDomainResource{}
)

// NewInternalDomainResource is a helper function to simplify the provider implementation.
func NewInternalDomainResource() resource.Resource {
	return &internalDomainResource{}
}

// internalDomainResource is the resource implementation.
type internalDomainResource struct {
	client internaldomains.APIClient
}

// internalDomainResourceModel maps the data schema data.
type internalDomainResourceModel struct {
	Id                      types.Int64  `tfsdk:"id"`
	Domain                  types.String `tfsdk:"domain"`
	Description             types.String `tfsdk:"description"`
	IncludeAllVAs           types.Bool   `tfsdk:"include_all_vas"`
	IncludeAllMobileDevices types.Bool   `tfsdk:"include_all_mobile_devices"`
	SiteIds                 types.List   `tfsdk:"site_ids"`
	CreatedAt               types.String `tfsdk:"created_at"`
	ModifiedAt              types.String `tfsdk:"modified_at"`
}

// Metadata returns the resource type name.
func (r *internalDomainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_internal_domain"
}

// Configure adds the provider configured client to the resource.
func (r *internalDomainResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetInternalDomainsClient(ctx)
}

// Schema defines the schema for the resource.
func (r *internalDomainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Cisco Secure Access Internal Domain resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of internal domain",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Description: "Domain name of internal domain",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of internal domain",
				Optional:    true,
			},
			"include_all_vas": schema.BoolAttribute{
				Description: "Whether or not to apply internal domain to all virtual appliances",
				Optional:    true,
			},
			"include_all_mobile_devices": schema.BoolAttribute{
				Description: "Whether or not to apply internal domain to all mobile devices",
				Optional:    true,
			},
			"site_ids": schema.ListAttribute{
				Description: "Site IDs associated with internal domain",
				Optional:    true,
				ElementType: types.Int64Type,
			},
			"created_at": schema.StringAttribute{
				Description: "Date and time when internal domain was created",
				Computed:    true,
			},
			"modified_at": schema.StringAttribute{
				Description: "Date and time when internal domain was modified",
				Computed:    true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *internalDomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Internal Domain")
	// Retrieve values from plan
	var plan internalDomainResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	planRep, _ := json.Marshal(plan)
	tflog.Debug(ctx, "Local internal domain definition", map[string]interface{}{"definition": string(planRep)})

	domain := plan.Domain.ValueString()
	createInternalDomainRequest := buildInternalDomainRequest(ctx, plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	var createResp *internaldomains.InternalDomainObject
	err := retry.Do(
		func() error {
			var httpRes *http.Response
			var err error
			createResp, httpRes, err = r.client.InternalDomainsAPI.CreateInternalDomain(ctx).CreateInternalDomainRequest(createInternalDomainRequest).Execute()
			if err != nil {
				if httpRes != nil {
					bodyBytes, _ := io.ReadAll(httpRes.Body)
					if httpRes.StatusCode == 409 || httpRes.StatusCode == 429 {
						return fmt.Errorf("retryable error (status %d): %v - %s", httpRes.StatusCode, err, string(bodyBytes))
					}
					resp.Diagnostics.AddError(
						"Error creating internal domain",
						fmt.Sprintf("Failed to create internal domain '%s': %v", domain, err),
					)
					return retry.Unrecoverable(err)
				}
				resp.Diagnostics.AddError(
					"Error creating internal domain",
					fmt.Sprintf("Failed to create internal domain '%s': %v", domain, err),
				)
				return retry.Unrecoverable(err)
			}
			return nil
		},
		retry.Attempts(retryMaxAttempts),
		retry.Delay(retryBaseDelay),
		retry.Context(ctx),
	)
	if err != nil {
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError(
				"Error creating internal domain",
				fmt.Sprintf("Failed to create internal domain '%s': %v", domain, err),
			)
		}
		return
	}

	tflog.Debug(ctx, "Created internal domain", map[string]interface{}{
		"id":     createResp.GetId(),
		"domain": domain,
	})

	setInternalDomainState(ctx, createResp, &plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *internalDomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state internalDomainResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	internalDomainId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Reading internal domain", map[string]interface{}{"id": internalDomainId})

	readResp, httpRes, err := r.client.InternalDomainsAPI.GetInternalDomain(ctx, internalDomainId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Internal domain not found, removing from state", map[string]interface{}{"id": internalDomainId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading internal domain",
			fmt.Sprintf("Could not read internal domain ID %d: %s", internalDomainId, err.Error()),
		)
		return
	}

	// Ensure httpRes is not nil before accessing its fields in Read
	if httpRes == nil {
		resp.Diagnostics.AddError(
			"HTTP Response Error",
			fmt.Sprintf("Received nil HTTP response while reading internal domain ID %d", internalDomainId),
		)
		return
	}

	setInternalDomainState(ctx, readResp, &state, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *internalDomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Internal Domain")

	// Retrieve values from plan and state
	var plan, state internalDomainResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	internalDomainId := plan.Id.ValueInt64()
	updateInternalDomainRequest := buildInternalDomainRequest(ctx, plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	var updateResp *internaldomains.InternalDomainObject
	err := retry.Do(
		func() error {
			var httpRes *http.Response
			var err error
			updateResp, httpRes, err = r.client.InternalDomainsAPI.UpdateInternalDomain(ctx, internalDomainId).CreateInternalDomainRequest(updateInternalDomainRequest).Execute()
			if err != nil {
				if httpRes != nil {
					bodyBytes, _ := io.ReadAll(httpRes.Body)
					if httpRes.StatusCode == 409 || httpRes.StatusCode == 429 {
						return fmt.Errorf("retryable error (status %d): %v - %s", httpRes.StatusCode, err, string(bodyBytes))
					}
					resp.Diagnostics.AddError(
						"Error updating internal domain",
						fmt.Sprintf("Could not update internal domain ID %d: %s", internalDomainId, err.Error()),
					)
					return retry.Unrecoverable(err)
				}
				resp.Diagnostics.AddError(
					"Error updating internal domain",
					fmt.Sprintf("Could not update internal domain ID %d: %s", internalDomainId, err.Error()),
				)
				return retry.Unrecoverable(err)
			}
			return nil
		},
		retry.Attempts(retryMaxAttempts),
		retry.Delay(retryBaseDelay),
		retry.Context(ctx),
	)
	if err != nil {
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError(
				"Error updating internal domain",
				fmt.Sprintf("Could not update internal domain ID %d: %s", internalDomainId, err.Error()),
			)
		}
		return
	}

	tflog.Debug(ctx, "Updated internal domain", map[string]interface{}{
		"id": internalDomainId,
	})

	setInternalDomainState(ctx, updateResp, &state, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the state with planned values
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *internalDomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state internalDomainResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	internalDomainId := state.Id.ValueInt64()
	tflog.Info(ctx, "Deleting internal domain", map[string]interface{}{"id": internalDomainId})

	// Delete existing internal domain
	var deleteResp interface{}
	var httpRes *http.Response
	err := retry.Do(
		func() error {
			var err error
			deleteResp, httpRes, err = r.client.InternalDomainsAPI.DeleteInternalDomain(ctx, internalDomainId).Execute()
			if httpRes != nil && httpRes.StatusCode == 404 {
				return nil
			}
			if err != nil {
				if httpRes != nil {
					bodyBytes, _ := io.ReadAll(httpRes.Body)
					if httpRes.StatusCode == 409 || httpRes.StatusCode == 429 {
						return fmt.Errorf("retryable error (status %d): %v - %s", httpRes.StatusCode, err, string(bodyBytes))
					}
					resp.Diagnostics.AddError(
						"Error deleting internal domain",
						fmt.Sprintf("Could not delete internal domain ID %d: %s", internalDomainId, err.Error()),
					)
					return retry.Unrecoverable(err)
				}
				resp.Diagnostics.AddError(
					"Error deleting internal domain",
					fmt.Sprintf("Could not delete internal domain ID %d: %s", internalDomainId, err.Error()),
				)
				return retry.Unrecoverable(err)
			}
			return nil
		},
		retry.Attempts(retryMaxAttempts),
		retry.Delay(retryBaseDelay),
		retry.Context(ctx),
	)
	if httpRes != nil && httpRes.StatusCode == 404 {
		// Resource already deleted
		tflog.Info(ctx, "Internal domain already deleted", map[string]interface{}{"id": internalDomainId})
		return
	}
	if err != nil {
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError(
				"Error deleting internal domain",
				fmt.Sprintf("Could not delete internal domain ID %d: %s", internalDomainId, err.Error()),
			)
		}
		return
	}

	tflog.Info(ctx, "Successfully deleted internal domain", map[string]interface{}{
		"id":       internalDomainId,
		"status":   httpRes.Status,
		"response": deleteResp,
	})
}

func buildInternalDomainRequest(ctx context.Context, plan internalDomainResourceModel, addError func(string, string)) internaldomains.CreateInternalDomainRequest {
	internalDomainRequest := *internaldomains.NewCreateInternalDomainRequest(plan.Domain.ValueString())

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		internalDomainRequest.SetDescription(plan.Description.ValueString())
	}
	if !plan.IncludeAllVAs.IsNull() && !plan.IncludeAllVAs.IsUnknown() {
		internalDomainRequest.SetIncludeAllVAs(plan.IncludeAllVAs.ValueBool())
	}
	if !plan.IncludeAllMobileDevices.IsNull() && !plan.IncludeAllMobileDevices.IsUnknown() {
		internalDomainRequest.SetIncludeAllMobileDevices(plan.IncludeAllMobileDevices.ValueBool())
	}
	if !plan.SiteIds.IsNull() && !plan.SiteIds.IsUnknown() {
		var siteIds []int64
		diags := plan.SiteIds.ElementsAs(ctx, &siteIds, false)
		if diags.HasError() {
			addError(
				"Error processing internal domain site IDs",
				"Could not convert site IDs to API request format",
			)
			return internalDomainRequest
		}
		internalDomainRequest.SetSiteIds(siteIds)
	}

	return internalDomainRequest
}

func setInternalDomainState(ctx context.Context, internalDomain *internaldomains.InternalDomainObject, state *internalDomainResourceModel, addError func(string, string)) {
	state.Id = types.Int64Value(internalDomain.GetId())
	state.Domain = types.StringValue(internalDomain.GetDomain())
	state.Description = types.StringValue(internalDomain.GetDescription())
	state.IncludeAllVAs = types.BoolValue(internalDomain.GetIncludeAllVAs())
	state.IncludeAllMobileDevices = types.BoolValue(internalDomain.GetIncludeAllMobileDevices())
	state.CreatedAt = types.StringValue(formatInternalDomainTime(internalDomain.GetCreatedAt()))
	state.ModifiedAt = types.StringValue(formatInternalDomainTime(internalDomain.GetModifiedAt()))

	siteIds, diags := types.ListValueFrom(ctx, types.Int64Type, internalDomain.GetSiteIds())
	if diags.HasError() {
		addError(
			"Error processing internal domain site IDs",
			"Could not convert site IDs to terraform state format",
		)
		return
	}
	state.SiteIds = siteIds
}

func formatInternalDomainTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}
