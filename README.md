# terraform-provider-ciscosecureaccess

A terraform provider for Cisco Secure Access. The provider communicates with Cisco Secure Access using the public REST APIs.

Documentation available at: https://registry.terraform.io/providers/CiscoDevNet/ciscosecureaccess/latest/docs

## Known Limitations

* NTGs only support static routes, no BGP support at this time.


## Requirements

* Terrafrom >= 1.1
* Go >= 1.23

## Usage

Provider releases are avaialable for automatic installation using `terraform init`. 

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


### Using a Pre-Compiled Provider Binary

A `terraform-provider-ciscosecureaccess` build can be placed in any [local mirror directory](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories) or in an existing [provider cache](https://developer.hashicorp.com/terraform/cli/config/config-file#implied-local-mirror-directories).  Tests have proved succesful when saving the provider to `./terraform.d/plugins/github.com/CiscoDevNet/ciscosecureaccess/1.0.0/$(GOOS)_$(GOARCH)/terraform-provider-ciscosecureaccess_v1.0.0` at the root of your terraform config:


```
terraform {
  required_providers {
    ciscosecureaccess = {
      source  = "github.com/CiscoDevNet/ciscosecureaccess"
      version = "~> 1.0.0"
    }
  }
}
```
