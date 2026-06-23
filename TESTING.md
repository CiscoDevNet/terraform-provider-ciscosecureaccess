# Testing Guide

## Prerequisites

- Go 1.24+
- Access to 1Password CLI (`op`) for credential retrieval
- Access to Cisco Conjur for API key retrieval

## Unit Tests (No API Calls)

Unit tests validate helper functions (flatten/expand logic) without hitting any external APIs.

```bash
cd terraform-provider-ciscosecureaccess

# Run all unit tests
go test -v -run "TestFlatten|TestGetContentCategoryLists" ./internal/provider/

# Run with race detection
go test -race -run "TestFlatten" ./internal/provider/

# Run with coverage
go test -cover -run "TestFlatten" ./internal/provider/
```

## Acceptance Tests (Real API)

Acceptance tests create, read, update, and delete real resources against the SecureAccess API. They require valid API credentials.

### Setup Credentials

The provider requires two environment variables:
- `CISCOSECUREACCESS_KEY_ID` — API client ID
- `CISCOSECUREACCESS_KEY_SECRET` — API client secret

These are stored in Conjur and accessed via the Conjur API key in 1Password.

#### One-liner setup (org 8218572)

```bash
CONJUR_PASSWORD=$(op item get --vault QE-dev "conjur-sbg/scalex/apikey_taas" --fields password --reveal) && \
TOKEN=$(curl -s --data "$CONJUR_PASSWORD" -H "Accept-Encoding: base64" "https://conjur-prod.cisco.com/authn/cisco/$(python3 -c 'import urllib.parse; print(urllib.parse.quote_plus("host/sbg/scalex/apikey_taas"))')/authenticate") && \
export CISCOSECUREACCESS_KEY_ID=$(curl -s -H "Authorization: Token token=\"$TOKEN\"" \
  "https://conjur-prod.cisco.com/secrets/cisco/variable/$(python3 -c 'import urllib.parse; print(urllib.parse.quote_plus("sbg/scalex/taas/umbrella/8218572_CONFIG_API_CLIENT_ID"))')") && \
export CISCOSECUREACCESS_KEY_SECRET=$(curl -s -H "Authorization: Token token=\"$TOKEN\"" \
  "https://conjur-prod.cisco.com/secrets/cisco/variable/$(python3 -c 'import urllib.parse; print(urllib.parse.quote_plus("sbg/scalex/taas/umbrella/8218572_CONFIG_API_CLIENT_KEY"))')")
```

#### For a different org

Replace `8218572` with your org ID in the Conjur paths:
- `sbg/scalex/taas/umbrella/<ORG_ID>_CONFIG_API_CLIENT_ID`
- `sbg/scalex/taas/umbrella/<ORG_ID>_CONFIG_API_CLIENT_KEY`

### Run Acceptance Tests

The `TF_ACC=1` flag enables acceptance tests. Without it, only unit tests run.

```bash
# Run a single resource test
TF_ACC=1 go test -v -run TestSiteResource_basic -timeout 120s ./internal/provider/

# Run all tests for a specific resource
TF_ACC=1 go test -v -run "TestAccZtnaProfile" -timeout 300s ./internal/provider/

# Run all ZTNA tests
TF_ACC=1 go test -v -run "TestAccZtnaProfile|TestAccZtnaTrustedNetwork|TestAccDataSourceZtna|TestAccZtnaPrivateSteeringDestination" -timeout 300s ./internal/provider/

# Run all acceptance tests
TF_ACC=1 go test -v -timeout 600s ./internal/provider/
```

### Available Test Suites

| Resource | Test Pattern | Notes |
|----------|-------------|-------|
| Site | `TestSiteResource` | |
| Internal Network | `TestInternalNetworkResource` | |
| Destination List | `TestDestinationListResource` | |
| Network Tunnel Group | `TestNTGResource` | |
| Private Resource | `TestPrivateResourceResource` | |
| Resource Connector Agent | `TestResourceConnectorAgentResource` | |
| SWG Device Settings | `TestSWGDeviceSettingsResource` | |
| ZTNA Profile | `TestAccZtnaProfile` | |
| ZTNA Trusted Network | `TestAccZtnaTrustedNetwork` | |
| ZTNA Profile Mappings | `TestAccZtnaProfilePrivateResourceMappings\|TestAccZtnaProfileInternetSteering\|TestAccZtnaPrivateSteeringDestination` | |
| Global Settings | `TestGlobalSettingsResource` | Requires `CISCOSECUREACCESS_TEST_GLOBAL_DECRYPTION` env var |
| Access Policy | `TestAccessPolicyResource` | Requires `CISCOSECUREACCESS_TEST_ACCESS_POLICY_ID` env var |
| Group Data Source | `TestGroupDataSource` | |
| Identity Data Source | `TestIdentityDataSource` | |
| Content Category List | `TestContentCategoryListDataSource` | Requires category settings API scope |
| ZTNA Profiles Data Source | `TestAccDataSourceZtnaProfiles` | |
| ZTNA Trusted Networks Data Source | `TestAccDataSourceZtnaTrustedNetworks` | |

### Run All Tests (Helper Script)

```bash
./run_tests.sh
```

Pass extra flags:

```bash
./run_tests.sh -run "TestAccZtnaProfile"
./run_tests.sh -count=1
```

### Rate Limiting

Tests are rate-limited to 1 concurrent test with a 5-second delay between tests to avoid API throttling. A full test suite run takes ~10-20 minutes.

---

## Cross-Compile for Docker

The infra-terraform Docker runner (`registry.strln.net/scalex/terraform-ciscosse:scalex`) runs linux/amd64. Cross-compile the provider binary before deploying to `local-providers/`:

```bash
cd terraform-provider-ciscosecureaccess

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o terraform-provider-ciscosecureaccess .

cp terraform-provider-ciscosecureaccess \
  ../cloudsec_scalex_infra-terraform/terraform/local-providers/ciscodevnet/ciscosecureaccess/terraform-provider-ciscosecureaccess
```

Verify the binary:

```bash
file ../cloudsec_scalex_infra-terraform/terraform/local-providers/ciscodevnet/ciscosecureaccess/terraform-provider-ciscosecureaccess
# Expected: ELF 64-bit LSB executable, x86-64, statically linked
```

---

## Run Terraform via infra-terraform (Docker Runner)

The `terraform-runner.sh` script mounts the repo into a Docker container. When `dev.tfrc` is present it uses the local provider binary instead of the registry version:

```hcl
# cloudsec_scalex_infra-terraform/terraform/dev.tfrc
provider_installation {
  dev_overrides {
    "CiscoDevNet/ciscosecureaccess" = "/work/local-providers/ciscodevnet/ciscosecureaccess"
  }
  direct {}
}
```

### Plan/Apply against an org

```bash
cd cloudsec_scalex_infra-terraform/terraform/ciscosse_orgs

ORG_ID=8218572 make plan
ORG_ID=8218572 make apply
ORG_ID=8218572 make destroy
```

### Available test orgs

| Org ID | Environment | Notes |
|--------|-------------|-------|
| 8218572 | Production (prep) | Primary acceptance test org, ZTNA enabled |
| 8376136 | Production (prep) | Secondary test org, ZTNA enabled |
| 8318025 | Production | ScaleX automation org |
| 8384421 | Production | Multi-region (us-west-1, ap-northeast-1) |
| 8263367 | Staging | `int.api.sse.cisco.com` |
| 8263368 | Staging | `int.api.sse.cisco.com` |
| 8253995 | China Dev | `api.dev.ciscosecureaccess.cn` |

### Debugging

```bash
TF_LOG=DEBUG ORG_ID=8218572 make plan
TF_RUNNER_DEBUG=1 ORG_ID=8218572 make plan
TAG=my-branch ORG_ID=8218572 make plan
```

---

## Quick Reference: Full Cycle

```bash
# 1. Edit code
vim internal/provider/resource_ztna_profile.go

# 2. Build + unit test
go build ./... && go test -race ./internal/provider/

# 3. Acceptance test (optional, slow)
./run_tests.sh -run "TestAccZtnaProfile"

# 4. Cross-compile and deploy to local-providers
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o terraform-provider-ciscosecureaccess .
cp terraform-provider-ciscosecureaccess \
  ../cloudsec_scalex_infra-terraform/terraform/local-providers/ciscodevnet/ciscosecureaccess/terraform-provider-ciscosecureaccess

# 5. Run against real org
cd ../cloudsec_scalex_infra-terraform/terraform/ciscosse_orgs
ORG_ID=8218572 make plan
ORG_ID=8218572 make apply
```

---

### Cleanup

If tests fail mid-run and leave dangling resources, clean them up via the API:

```bash
# Get a bearer token
API_TOKEN=$(curl -s -X POST "https://api.sse.cisco.com/auth/v2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -u "$CISCOSECUREACCESS_KEY_ID:$CISCOSECUREACCESS_KEY_SECRET" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List ZTNA profiles (look for tfAcc prefixed names)
curl -s -H "Authorization: Bearer $API_TOKEN" \
  "https://api.sse.cisco.com/deployments/v2/ztna/profiles" | python3 -m json.tool

# Delete a dangling profile
curl -X DELETE -H "Authorization: Bearer $API_TOKEN" \
  "https://api.sse.cisco.com/deployments/v2/ztna/profiles/<PROFILE_ID>"

# List and delete dangling destination lists
curl -s -H "Authorization: Bearer $API_TOKEN" \
  "https://api.sse.cisco.com/policies/v2/destinationlists" | python3 -m json.tool

curl -X DELETE -H "Authorization: Bearer $API_TOKEN" \
  "https://api.sse.cisco.com/policies/v2/destinationlists/<LIST_ID>"
```

Test resources use the prefix `tfAcc` in their names for easy identification.
