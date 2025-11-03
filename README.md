# esphome DNS Rewrite Proxy

This ESPHome component acts as a DNS proxy that rewrites DNS queries based on user-defined rules.

Records not found in the rewrite rules are forwarded to the upstream DNS server from the current network configuration.

Tested on `ESP32-C3` and `ESP32-S3` devices. Support for `ESP8266` is not available due to memory constraints.

## Konfiguration Example

```yaml

external_components:
  - source: github://b2un0/esphome-dns-rewrite-proxy@main

dns_proxy:
  id: dns_server
  records:
    - domain: "tc.fritz.box"
      ip: "192.168.155.250"
    - domain: "geo.hivebedrock.network"
      ip: "192.168.155.15"
    - domain: "play.inpvp.net"
      ip: "192.168.155.15"
    - domain: "mco.lbsg.net"
      ip: "192.168.155.15"
    - domain: "play.galaxite.net"
      ip: "192.168.155.15"
    - domain: "hivebedrock.network"
      ip: "192.168.155.15"
    - domain: "mco.cubecraft.net"
      ip: "192.168.155.15"
    - domain: "mco.mineplex.com"
      ip: "192.168.155.15"
```

## Sensors

```yaml
sensor:
  - platform: template
    name: "DNS Query Count"
    id: query_count_sensor
    accuracy_decimals: 0
    state_class: "total_increasing"
    icon: "mdi:dns"
    lambda: |-
      return id(dns_server).get_query_count();
    update_interval: 10s

  - platform: template
    name: "DNS Forwarded Count"
    id: forwarded_count_sensor
    accuracy_decimals: 0
    state_class: "total_increasing"
    icon: "mdi:dns-outline"
    lambda: |-
      return id(dns_server).get_forwarded_count();
    update_interval: 10s

  - platform: template
    name: "DNS Records Count"
    id: record_count_sensor
    accuracy_decimals: 0
    state_class: "measurement"
    icon: "mdi:database"
    lambda: |-
      return id(dns_server).get_record_count();
    update_interval: 60s
```

## Test if rewrite works

in case the esp device has the ip `192.168.155.51` and you have the `tc.fritz.box` domain rewritten, you can test it
with:

```shell
nslookup tc.fritz.box 192.168.155.51
```

the answer should be something like:

```plain
Server:         192.168.155.51
Address:        192.168.155.51#53

Non-authoritative answer:
Name:   tc.fritz.box
Address: 192.168.155.250

```

and in the esp log you should see something like:

```plain
[D][dns_redirect:171]: DNS query for: tc.fritz.box (ID: b6e8)
[D][dns_redirect:187]: Local response: 192.168.155.250
```

## Test if forwarding works

for a domain that is not rewritten, e.g. `esphome.io`:

```shell
nslookup esphome.io 192.168.155.51
```

the answer should be something like:

```plain
Server:         192.168.155.51
Address:        192.168.155.51#53

Non-authoritative answer:
Name:   esphome.io
Address: 104.21.87.21
Name:   esphome.io
Address: 172.67.168.170
```

and in the esp log you should see something like:

```plain
[D][dns_redirect:171]: DNS query for: esphome.io (ID: c1fe)
[D][dns_redirect:228]: Forwarded query (ID: c1fe -> 9145)
[D][dns_redirect:309]: Forwarded response (ID: 9145 -> c1fe)
```

## Note

IPv6 is not supported at the moment.
