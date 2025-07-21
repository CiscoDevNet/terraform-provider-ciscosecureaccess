resource "ciscosecureaccess_private_resource" "test_resource" {
  name = "Test application"
  access_types = ["network"]
  description = "Application used for performing tests"
  addresses = [{
    addresses = ["10.10.110.2/32"]
    traffic_selector = [
      { ports = "443", protocol = "http/https" },
      { ports = "5443", protocol = "udp" }
    ]
  }]
}

resource "ciscosecureaccess_private_resource" "ztna_resource" {
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
