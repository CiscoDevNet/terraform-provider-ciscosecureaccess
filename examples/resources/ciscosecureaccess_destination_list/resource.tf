resource "ciscosecureaccess_destination_list" "test_dl1" {
    name = "TF Dest List A"
    destinations = [
      {
        comment = "Second warning url managed by TF"
        type = "ipv4"
        destination = "127.0.0.2"
      },
      {
        comment = "First warning url managed by TF"
        type = "domain"
        destination = "warn.foo.bar"
      },
      {
        comment = "Second warning url managed by TF"
        type = "url"
        destination = "http://foo.bar/blockwarn"
      }
    ]
}
