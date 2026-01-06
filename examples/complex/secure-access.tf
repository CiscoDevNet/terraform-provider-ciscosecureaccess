terraform {
  required_version = "~> 1.1"
  required_providers {
    ciscosecureaccess = {
      source  = "CiscoDevNet/ciscosecureaccess"
      version = "~> 1.0.0"
    }
  }
}

provider "ciscosecureaccess" {
}

resource "ciscosecureaccess_destination_list" "test_dl1" {
    name = "TF Dest List A"
    destinations = [
      {
        comment = "First warning url managed by TF"
        type = "ipv4"
        destination = "127.0.0.2"
      },
      {
        comment = "Second warning url managed by TF"
        type = "url"
        destination = "http://foo.bar/blockwarn"
      },
      {
        comment = "Next warning url managed by TF"
        type = "domain"
        destination = "warn.foo.bar"
      }
    ]
}

resource "ciscosecureaccess_network_tunnel_group" "test_tunnel1" {
    name = "TF Test Tunnel 1"
    network_cidrs = ["10.17.177.0/24"]
    region = "us-test-2"
    identifier_prefix = "tftesttunnel1"
    preshared_key = "Testing1Testing1"
    device_type = "other"
}

resource "ciscosecureaccess_network_tunnel_group" "test_tunnel2" {
    name = "TF Test Tunnel 2"
    network_cidrs = ["10.17.178.0/24"]
    region = "us-test-2"
    identifier_prefix = "tftesttunnel2"
    preshared_key = "Testing1Testing1"
    device_type = "other"
}

resource "ciscosecureaccess_private_resource" "test_resource" {
    name = "TF-Test-Private-Resource"
    access_types = ["network"]
    description = "Test resource for terraform access policy support"
    addresses = [{
      addresses = ["10.17.178.2/32"]
      traffic_selector = [
        { ports = "443", protocol = "http/https" },
        { ports = "5443", protocol = "udp" }
      ]
    }]
}

resource "ciscosecureaccess_private_resource" "test_ztna_resource" {
    name = "TF-Test-ZTNA-Resource"
    access_types = ["client"]
    client_reachable_addresses = ["10.10.10.3"]
    description = "Test ZTNA resource for terraform access policy support"
    addresses = [{
      addresses = ["10.10.10.3/32"]
      traffic_selector = [
        { ports = "443", protocol = "http/https" },
      ]
    }]
}

resource "ciscosecureaccess_access_policy" "tunnel_to_pa" {
    name = "terraform-private-policy"
    action = "allow"
    enabled = true
    log_level = "LOG_ALL"
    source_ids = [resource.ciscosecureaccess_network_tunnel_group.test_tunnel1.id]
    private_resource_ids = [resource.ciscosecureaccess_private_resource.test_resource.id]
    description = "Test rule for terraform private access policy support"
}

resource "ciscosecureaccess_access_policy" "user_to_internet" {
    name = "terraform-internet-policy"
    action = "allow"
    enabled = true
    log_level = "LOG_ALL"
    traffic_type = "PUBLIC_INTERNET"
    source_ids = [data.ciscosecureaccess_identity.identity.identities[0].id ]
    destination_list_ids = [resource.ciscosecureaccess_destination_list.test_dl1.id ]
    description = "Test rule for terraform internet access policy support"
}

data "ciscosecureaccess_identity" "identity" {
  filter = "testusername" //replace with the username of an identity from Secure Access

}

output "identity_out" {
  value = data.ciscosecureaccess_identity.identity.identities
}
