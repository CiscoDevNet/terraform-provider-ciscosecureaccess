// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"golang.org/x/oauth2/clientcredentials"
)

const defaultSSEAPIEndpoint = "api.sse.cisco.com"

type reportsIdentityClient struct {
	httpClient         *http.Client
	identitiesEndpoint string
}

func newReportsIdentityClient(ctx context.Context, factory *client.SSEClientFactory) *reportsIdentityClient {
	apiEndpoint := factory.ApiEndpoint
	if apiEndpoint == "" {
		apiEndpoint = defaultSSEAPIEndpoint
	}

	tokenConfig := clientcredentials.Config{
		ClientID:     factory.KeyId,
		ClientSecret: factory.KeySecret,
		TokenURL:     fmt.Sprintf("https://%s/auth/v2/token", apiEndpoint),
	}
	httpClient := tokenConfig.Client(ctx)
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &reportsIdentityClient{
		httpClient:         httpClient,
		identitiesEndpoint: fmt.Sprintf("https://%s/reports/v2/identities", apiEndpoint),
	}
}

func (c *reportsIdentityClient) getIdentities(
	ctx context.Context,
	limit int64,
	offset int64,
	search string,
	identityType string,
) (*reports.GetIdentities200Response, *http.Response, error) {
	for redirectCount := 0; redirectCount < 2; redirectCount++ {
		requestURL, err := url.Parse(c.identitiesEndpoint)
		if err != nil {
			return nil, nil, fmt.Errorf("parse reports identities endpoint: %w", err)
		}

		query := requestURL.Query()
		query.Set("limit", fmt.Sprintf("%d", limit))
		query.Set("offset", fmt.Sprintf("%d", offset))
		query.Set("search", search)
		query.Set("identitytypes", identityType)
		requestURL.RawQuery = query.Encode()

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("create reports identities request: %w", err)
		}

		response, err := c.httpClient.Do(request)
		if err != nil {
			return nil, response, err
		}

		if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
			location, locationErr := response.Location()
			response.Body.Close()
			if locationErr != nil {
				return nil, response, fmt.Errorf("resolve reports identities redirect: %w", locationErr)
			}
			if !isTrustedReportsEndpoint(location) {
				return nil, response, fmt.Errorf("reports identities redirect target is not a trusted Cisco endpoint: %s", location.Hostname())
			}
			location.RawQuery = ""
			c.identitiesEndpoint = location.String()
			continue
		}

		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			response.Body.Close()
			return nil, response, fmt.Errorf("reports identities request returned HTTP %d", response.StatusCode)
		}

		var identitiesResponse reports.GetIdentities200Response
		if err := json.NewDecoder(response.Body).Decode(&identitiesResponse); err != nil {
			response.Body.Close()
			return nil, response, fmt.Errorf("decode reports identities response: %w", err)
		}
		response.Body.Close()
		return &identitiesResponse, response, nil
	}

	return nil, nil, fmt.Errorf("reports identities endpoint returned too many redirects")
}

func isTrustedReportsEndpoint(endpoint *url.URL) bool {
	if endpoint.Scheme != "https" {
		return false
	}

	hostname := strings.ToLower(endpoint.Hostname())
	return hostname == "api.umbrella.com" ||
		strings.HasSuffix(hostname, ".umbrella.com") ||
		strings.HasSuffix(hostname, ".cisco.com") ||
		strings.HasSuffix(hostname, ".ciscosecureaccess.cn")
}
