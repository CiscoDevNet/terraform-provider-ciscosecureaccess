#!/usr/bin/env bash
set -euo pipefail

CONJUR_APIKEY_SECRET="$(op item get --vault QE-dev 'conjur-sbg/scalex/apikey_taas' --fields password --reveal)"
CONJUR_URL="https://conjur-prod.cisco.com"
CONJUR_ACCOUNT="cisco"
CONJUR_HOST="host/sbg/scalex/apikey_taas"
ORG_ID="8218572"

CONJUR_TOKEN=$(curl -s --request POST \
  "${CONJUR_URL}/authn/${CONJUR_ACCOUNT}/$(python3 -c "import urllib.parse; print(urllib.parse.quote('${CONJUR_HOST}', safe=''))")/authenticate" \
  --data "${CONJUR_APIKEY_SECRET}" \
  -H "Accept-Encoding: base64")

export CISCOSECUREACCESS_KEY_ID=$(curl -s -H "Authorization: Token token=\"${CONJUR_TOKEN}\"" \
  "${CONJUR_URL}/secrets/${CONJUR_ACCOUNT}/variable/$(python3 -c "import urllib.parse; print(urllib.parse.quote('sbg/scalex/taas/umbrella/${ORG_ID}_CONFIG_API_CLIENT_ID', safe=''))")")

export CISCOSECUREACCESS_KEY_SECRET=$(curl -s -H "Authorization: Token token=\"${CONJUR_TOKEN}\"" \
  "${CONJUR_URL}/secrets/${CONJUR_ACCOUNT}/variable/$(python3 -c "import urllib.parse; print(urllib.parse.quote('sbg/scalex/taas/umbrella/${ORG_ID}_CONFIG_API_CLIENT_KEY', safe=''))")")

export TF_ACC=1

exec go test -race -v -run ".*" ./internal/provider/ -timeout 20m "$@"
