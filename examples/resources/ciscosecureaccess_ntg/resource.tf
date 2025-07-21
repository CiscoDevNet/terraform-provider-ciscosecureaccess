resource "ciscosecureaccess_network_tunnel_group" "test_tunnel1" {
    name = "TF Test Tunnel 1"
    network_cidrs = ["10.10.110.0/24"]
    region = "us-test-2"
    identifier_prefix = "remoteapptunnel"
    preshared_key = "redactedredacted"
    device_type = "other"
}
