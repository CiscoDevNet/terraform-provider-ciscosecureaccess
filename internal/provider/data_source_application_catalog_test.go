// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadApplicationCatalogEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/reports/v2/applications", request.URL.Path)
		assert.Equal(t, "Slack", request.URL.Query().Get("application"))
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{
  "data": {
    "applications": [
      {"id": "41", "label": "Slack", "type": "NBAR", "category": {"id": "9", "label": "Collaboration"}},
      {"id": "41", "label": "Slack", "type": "AVC", "category": {"id": "9", "label": "Collaboration"}}
    ],
    "categories": []
  },
  "meta": {}
}`)
	}))
	defer server.Close()

	apiClient := testReportsAPIClient(server)
	application, response, err := readApplicationCatalogEntry(context.Background(), apiClient, "Slack", "AVC")
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, int64(41), application.GetId())
	assert.Equal(t, "AVC", application.GetType())
	require.NotNil(t, application.Category)
	assert.Equal(t, "Collaboration", application.Category.GetLabel())
}

func TestSelectApplicationErrors(t *testing.T) {
	id := int64(41)
	name := "Slack"
	typeAVC := "AVC"

	t.Run("not found", func(t *testing.T) {
		_, err := selectApplication(nil, name, typeAVC)
		assert.ErrorContains(t, err, "no application found")
	})

	t.Run("duplicate", func(t *testing.T) {
		applications := []reports.Application{
			{Id: &id, Label: &name, Type: &typeAVC},
			{Id: &id, Label: &name, Type: &typeAVC},
		}
		_, err := selectApplication(applications, name, typeAVC)
		assert.ErrorContains(t, err, "catalog response is ambiguous")
	})

	t.Run("missing id", func(t *testing.T) {
		applications := []reports.Application{{Label: &name, Type: &typeAVC}}
		_, err := selectApplication(applications, name, typeAVC)
		assert.ErrorContains(t, err, "missing a required")
	})
}

func TestReadApplicationCategory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/reports/v2/applications", request.URL.Path)
		assert.Empty(t, request.URL.Query().Get("application"))
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{
  "data": {
    "applications": [],
    "categories": [{"id": "33", "name": "Social Networking"}]
  },
  "meta": {}
}`)
	}))
	defer server.Close()

	category, response, err := readApplicationCategory(context.Background(), testReportsAPIClient(server), "Social Networking")
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, int64(33), category.GetId())
	assert.Equal(t, "Social Networking", category.GetName())
}

func TestSelectApplicationCategoryErrors(t *testing.T) {
	id := int64(33)
	name := "Social Networking"

	_, err := selectApplicationCategory(nil, name)
	assert.ErrorContains(t, err, "no application category found")

	categories := []reports.ApplicationCategories{
		{Id: &id, Name: &name},
		{Id: &id, Name: &name},
	}
	_, err = selectApplicationCategory(categories, name)
	assert.ErrorContains(t, err, "catalog response is ambiguous")

	categories = []reports.ApplicationCategories{{Name: &name}}
	_, err = selectApplicationCategory(categories, name)
	assert.ErrorContains(t, err, "missing a required")
}

func TestReadWebCategory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/reports/v2/categories", request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{
  "data": [
    {"id": 24, "legacyid": 24, "label": "Social Networking", "type": "content", "integration": false, "deprecated": false}
  ],
  "meta": {}
}`)
	}))
	defer server.Close()

	category, response, err := readWebCategory(context.Background(), testReportsAPIClient(server), "Social Networking", "content")
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, int64(24), category.Id)
	assert.Equal(t, int64(24), category.Legacyid)
	assert.False(t, category.Deprecated)
}

func TestSelectWebCategory(t *testing.T) {
	categories := []reports.CategoryWithLegacyId{
		{Id: 24, Legacyid: 24, Label: "Social Networking", Type: "content"},
		{Id: 124, Legacyid: 124, Label: "Social Networking", Type: "integration"},
	}

	category, err := selectWebCategory(categories, "Social Networking", "content")
	require.NoError(t, err)
	assert.Equal(t, int64(24), category.Id)

	_, err = selectWebCategory(categories, "Social Networking", "")
	assert.ErrorContains(t, err, "set type to disambiguate")

	_, err = selectWebCategory(categories, "Missing", "content")
	assert.ErrorContains(t, err, "no web category found")
}

func testReportsAPIClient(server *httptest.Server) *reports.APIClient {
	configuration := reports.NewConfiguration()
	configuration.Servers[0].URL = server.URL
	configuration.HTTPClient = server.Client()
	return reports.NewAPIClient(configuration)
}
