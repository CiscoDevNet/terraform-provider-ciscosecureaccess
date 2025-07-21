# terraform-provider-ciscosecureaccess

A terraform provider for Cisco Secure Access

## Known Limitations

* NTGs only support static routes, no BGP support at this time.

## Usage

### Deploy an example config

To install the provider in a local mirror directory:

```
./examples/install.sh
cd terraform
terraform init
```

For a successful deployment, update data.ciscosecureaccess_identity.identity.filter in terraform/secure-access.tf to reflect a real user identity from your Secure Access deployment.

See "Initialize the Provider" below for providing Secure Access credentials.

### Using a Pre-Compiled Provider Binary

A `terraform-provider-ciscosecureaccess` build can be placed in any [local mirror directory](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories) or in an existing [provider cache](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories).  Tests have proved succesful when saving the provider to `./terraform.d/plugins/github.com/CiscoDevNet/ciscosecureaccess/0.0.1/$(GOOS)_$(GOARCH)/terraform-provider-ciscosecureaccess_v0.0.1` at the root of your terraform config:


```
terraform {
  required_providers {
    ciscosecureaccess = {
      source  = "github.com/CiscoDevNet/ciscosecureaccess"
      version = "~> 0.0.1"
    }
  }
}
```

See [secure-access.tf](./examples/complex/secure-access.tf) for a more complete example.

### Initialize the Provider

By default, the provider can pull Secure Access API key credentials from the environment variables `CISCOSECUREACCESS_KEY_ID` and `CISCOSECUREACCESS_KEY_SECRET`.

The provider can also be initialized using credentials from any terraform variable value. For example:

```
provider "ciscosecureaccess" {
    key_id: var.SECURE_ACCESS_KEY_ID
    key_secret: var.SECURE_ACCESS_KEY_SECRET
}
```
