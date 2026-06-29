// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
)

// The reports API currently returns application catalog IDs as either JSON
// numbers or quoted numbers, depending on the organization.
type flexibleInt64 int64

func (value *flexibleInt64) UnmarshalJSON(data []byte) error {
	var number int64
	if err := json.Unmarshal(data, &number); err == nil {
		*value = flexibleInt64(number)
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("expected an integer or quoted integer: %w", err)
	}
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid quoted integer %q: %w", text, err)
	}

	*value = flexibleInt64(number)
	return nil
}

type applicationCatalogWireResponse struct {
	Data struct {
		Applications []struct {
			ID       *flexibleInt64 `json:"id"`
			Label    *string        `json:"label"`
			Type     *string        `json:"type"`
			Category *struct {
				ID    *flexibleInt64 `json:"id"`
				Label *string        `json:"label"`
			} `json:"category"`
		} `json:"applications"`
		Categories []struct {
			ID   *flexibleInt64 `json:"id"`
			Name *string        `json:"name"`
		} `json:"categories"`
	} `json:"data"`
	Meta map[string]interface{} `json:"meta"`
}

func readApplicationCatalog(ctx context.Context, apiClient *reports.APIClient, applicationFilter string) (*reports.GetApplications200Response, *http.Response, error) {
	request := apiClient.DefaultAPI.GetApplications(ctx)
	if applicationFilter != "" {
		request = request.Application(applicationFilter)
	}

	result, httpResponse, err := request.Execute()
	if err == nil {
		return result, httpResponse, nil
	}
	if httpResponse == nil || httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return nil, httpResponse, err
	}

	result, compatibilityErr := decodeApplicationCatalogCompatibility(err)
	if compatibilityErr != nil {
		return nil, httpResponse, fmt.Errorf("generated decoder failed: %v; compatibility decoder failed: %w", err, compatibilityErr)
	}
	return result, httpResponse, nil
}

func decodeApplicationCatalogCompatibility(apiError error) (*reports.GetApplications200Response, error) {
	var openAPIError *reports.GenericOpenAPIError
	if !errors.As(apiError, &openAPIError) || len(openAPIError.Body()) == 0 {
		return nil, fmt.Errorf("reports error does not include a response body")
	}

	var wireResponse applicationCatalogWireResponse
	if err := json.Unmarshal(openAPIError.Body(), &wireResponse); err != nil {
		return nil, fmt.Errorf("decode application catalog compatibility response: %w", err)
	}

	applications := make([]reports.Application, 0, len(wireResponse.Data.Applications))
	for _, wireApplication := range wireResponse.Data.Applications {
		application := reports.Application{
			Id:    flexibleInt64Pointer(wireApplication.ID),
			Label: wireApplication.Label,
			Type:  wireApplication.Type,
		}
		if wireApplication.Category != nil {
			application.Category = &reports.ApplicationCategory{
				Id:    flexibleInt64Pointer(wireApplication.Category.ID),
				Label: wireApplication.Category.Label,
			}
		}
		applications = append(applications, application)
	}

	categories := make([]reports.ApplicationCategories, 0, len(wireResponse.Data.Categories))
	for _, wireCategory := range wireResponse.Data.Categories {
		categories = append(categories, reports.ApplicationCategories{
			Id:   flexibleInt64Pointer(wireCategory.ID),
			Name: wireCategory.Name,
		})
	}

	return &reports.GetApplications200Response{
		Data: reports.ApplicationsWithCategories{
			Applications: applications,
			Categories:   categories,
		},
		Meta: wireResponse.Meta,
	}, nil
}

func flexibleInt64Pointer(value *flexibleInt64) *int64 {
	if value == nil {
		return nil
	}
	number := int64(*value)
	return &number
}
