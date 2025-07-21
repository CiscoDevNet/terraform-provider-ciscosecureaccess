# Authenticate to the provider using Cisco Secure Access API keys
# Keys can be set in configuration, or via CISCOSECUREACCESS_KEY_ID and CISCOSECUREACCESS_KEY_SECRET environment variables
provider "ciscosecureaccess" {
  key_id = "examplekeyidfromdashboard"
  key_secret = "examplekeysecretfromdashboard"
}
