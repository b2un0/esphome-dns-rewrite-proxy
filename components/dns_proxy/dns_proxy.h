#pragma once

#include "esphome/core/component.h"
#include "esphome/components/sensor/sensor.h"
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <lwip/dns.h>
#include <lwip/ip4_addr.h>
#include <esp_heap_caps.h>
#include <esp_netif.h>
#include <map>
#include <vector>
#include <cstring>

namespace esphome {
namespace dns_proxy {

struct PendingQuery {
  ip_addr_t client_addr;
  u16_t client_port;
  uint16_t transaction_id;
  uint32_t timestamp;
};

class DnsRedirect : public Component {
 public:
  void add_record(const std::string &domain, const std::string &ip) {
    records_[domain] = parse_ip(ip);
    ESP_LOGI("dns_proxy", "Added DNS record: %s -> %s", domain.c_str(), ip.c_str());
  }

  uint32_t get_query_count() const { return query_count_; }
  uint32_t get_forwarded_count() const { return forwarded_count_; }
  uint32_t get_record_count() const { return records_.size(); }
  std::string get_last_query() const { return last_query_; }
  bool is_running() const { return udp_pcb_ != nullptr; }
  bool has_upstream_dns() const { return has_upstream_dns_; }
  uint32_t get_free_heap() const { return heap_caps_get_free_size(MALLOC_CAP_DEFAULT); }

  void setup() override {

#ifdef ARDUINO_ARCH_ESP8266
    // ESP8266 is not supported due to memory and lwIP differences.
    ESP_LOGE("dns_proxy", "ESP8266 is not supported by dns_proxy; component requires ESP32");
    this->mark_failed();
    return;
#endif

    // Get WiFi DNS server
    get_wifi_dns_server();

    // Use tcpip_callback to ensure thread safety
    tcpip_callback([](void* arg) {
      DnsRedirect* self = static_cast<DnsRedirect*>(arg);
      self->setup_udp();
    }, this);
  }

  void loop() override {
    // Cleanup old pending queries (timeout after 5 seconds)
    uint32_t now = millis();
    auto it = pending_queries_.begin();
    while (it != pending_queries_.end()) {
      if (now - it->second.timestamp > 5000) {
        it = pending_queries_.erase(it);
      } else {
        ++it;
      }
    }
  }

  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void get_wifi_dns_server() {
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif != nullptr) {
      esp_netif_dns_info_t dns_info;
      if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns_info) == ESP_OK) {
        // Convert esp_ip_addr_t to lwip ip_addr_t
        if (dns_info.ip.type == ESP_IPADDR_TYPE_V4) {
          ip_addr_set_ip4_u32(&upstream_dns_, dns_info.ip.u_addr.ip4.addr);
          has_upstream_dns_ = true;

          uint32_t dns_addr = dns_info.ip.u_addr.ip4.addr;
          ESP_LOGI("dns_proxy", "Using upstream DNS: %d.%d.%d.%d",
                   (dns_addr >> 0) & 0xFF, (dns_addr >> 8) & 0xFF,
                   (dns_addr >> 16) & 0xFF, (dns_addr >> 24) & 0xFF);
        } else {
          has_upstream_dns_ = false;
          ESP_LOGW("dns_proxy", "IPv6 DNS not supported - forwarding disabled");
        }
      } else {
        has_upstream_dns_ = false;
        ESP_LOGW("dns_proxy", "Could not get WiFi DNS - forwarding disabled");
      }
    } else {
      has_upstream_dns_ = false;
      ESP_LOGW("dns_proxy", "Could not get WiFi interface - forwarding disabled");
    }
  }

  void setup_udp() {
    // Server PCB (port 53)
    udp_pcb_ = udp_new();
    if (udp_pcb_ == nullptr) {
      ESP_LOGE("dns_proxy", "Failed to create server UDP PCB");
      mark_failed();
      return;
    }

    err_t err = udp_bind(udp_pcb_, IP_ADDR_ANY, 53);
    if (err != ERR_OK) {
      ESP_LOGE("dns_proxy", "Failed to bind UDP port 53: %d", err);
      udp_remove(udp_pcb_);
      udp_pcb_ = nullptr;
      mark_failed();
      return;
    }

    udp_recv(udp_pcb_, &DnsRedirect::udp_recv_callback, this);

    // Client PCB for forwarding (only if we have upstream DNS)
    if (has_upstream_dns_) {
      client_pcb_ = udp_new();
      if (client_pcb_ == nullptr) {
        ESP_LOGE("dns_proxy", "Failed to create client UDP PCB");
        mark_failed();
        return;
      }

      udp_recv(client_pcb_, &DnsRedirect::udp_forward_callback, this);
      ESP_LOGI("dns_proxy", "DNS proxy started on port 53 with forwarding");
    } else {
      ESP_LOGI("dns_proxy", "DNS server started on port 53 (local records only)");
    }

    ESP_LOGI("dns_proxy", "Configured %d DNS records", records_.size());
  }

  static void udp_recv_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *addr, u16_t port) {
    DnsRedirect *self = static_cast<DnsRedirect *>(arg);
    if (p != nullptr) {
      self->handle_dns_request(pcb, p, addr, port);
      pbuf_free(p);
    }
  }

  static void udp_forward_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                                   const ip_addr_t *addr, u16_t port) {
    DnsRedirect *self = static_cast<DnsRedirect *>(arg);
    if (p != nullptr) {
      self->handle_forwarded_response(pcb, p, addr, port);
      pbuf_free(p);
    }
  }

  void handle_dns_request(struct udp_pcb *pcb, struct pbuf *p,
                          const ip_addr_t *addr, u16_t port) {
    if (p->len < 12) return;

    uint8_t *data = static_cast<uint8_t *>(p->payload);

    // Parse query name
    std::string query_name = parse_dns_name(data + 12, p->len - 12);
    uint16_t transaction_id = (data[0] << 8) | data[1];

    query_count_++;
    last_query_ = query_name;

    ESP_LOGD("dns_proxy", "DNS query for: %s (ID: %04x)", query_name.c_str(), transaction_id);

    // Check if we have a local record
    uint32_t reply_ip = get_reply_ip(query_name);

    if (reply_ip != 0) {
      // We have a local record - respond directly
      std::vector<uint8_t> response;
      build_dns_response(data, p->len, reply_ip, response);

      struct pbuf *out = pbuf_alloc(PBUF_TRANSPORT, response.size(), PBUF_RAM);
      if (out != nullptr) {
        memcpy(out->payload, response.data(), response.size());
        udp_sendto(pcb, out, addr, port);
        pbuf_free(out);

        ESP_LOGD("dns_proxy", "Local response: %d.%d.%d.%d",
                 (reply_ip >> 0) & 0xFF, (reply_ip >> 8) & 0xFF,
                 (reply_ip >> 16) & 0xFF, (reply_ip >> 24) & 0xFF);
      }
    } else if (has_upstream_dns_) {
      // Forward to upstream DNS if available
      forward_query(data, p->len, addr, port, transaction_id);
    } else {
      // No local record and no upstream DNS - send NXDOMAIN
      send_nxdomain_response(data, p->len, pcb, addr, port);
    }
  }

  void forward_query(uint8_t *data, size_t len, const ip_addr_t *client_addr,
                     u16_t client_port, uint16_t original_id) {
    // Generate new transaction ID for upstream query
    uint16_t new_id = esp_random() & 0xFFFF;

    // Store pending query
    PendingQuery pending;
    pending.client_addr = *client_addr;
    pending.client_port = client_port;
    pending.transaction_id = original_id;
    pending.timestamp = millis();
    pending_queries_[new_id] = pending;

    // Modify transaction ID in query
    data[0] = (new_id >> 8) & 0xFF;
    data[1] = new_id & 0xFF;

    // Forward to upstream DNS
    struct pbuf *forward_p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (forward_p != nullptr) {
      memcpy(forward_p->payload, data, len);

      err_t err = udp_sendto(client_pcb_, forward_p, &upstream_dns_, 53);
      pbuf_free(forward_p);

      if (err == ERR_OK) {
        forwarded_count_++;

        ESP_LOGD("dns_proxy", "Forwarded query (ID: %04x -> %04x)", original_id, new_id);
      } else {
        // Remove from pending on error
        pending_queries_.erase(new_id);
        ESP_LOGW("dns_proxy", "Failed to forward query: %d", err);
      }
    }
  }

  // ... All other methods remain unchanged ...
  void send_nxdomain_response(uint8_t *request, size_t request_len,
                              struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port) {
    std::vector<uint8_t> response;
    response.reserve(512);

    // Copy transaction ID
    response.push_back(request[0]);
    response.push_back(request[1]);

    // Flags: Response, Authoritative, NXDOMAIN (RCODE = 3)
    response.push_back(0x81);
    response.push_back(0x83);  // NXDOMAIN

    // Question count (copy from request)
    response.push_back(request[4]);
    response.push_back(request[5]);

    // Answer, Authority, Additional = 0
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);

    // Copy question section
    size_t pos = 12;
    while (pos < request_len && request[pos] != 0) {
      response.push_back(request[pos++]);
    }
    if (pos < request_len) response.push_back(request[pos++]); // null terminator

    // Copy QTYPE and QCLASS (4 bytes)
    for (int i = 0; i < 4 && pos < request_len; i++) {
      response.push_back(request[pos++]);
    }

    // Send NXDOMAIN response
    struct pbuf *out = pbuf_alloc(PBUF_TRANSPORT, response.size(), PBUF_RAM);
    if (out != nullptr) {
      memcpy(out->payload, response.data(), response.size());
      udp_sendto(pcb, out, addr, port);
      pbuf_free(out);

      ESP_LOGD("dns_proxy", "Sent NXDOMAIN response");
    }
  }

  void handle_forwarded_response(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *addr, u16_t port) {
    if (p->len < 12) return;

    uint8_t *data = static_cast<uint8_t *>(p->payload);
    uint16_t response_id = (data[0] << 8) | data[1];

    // Find pending query
    auto it = pending_queries_.find(response_id);
    if (it != pending_queries_.end()) {
      PendingQuery &pending = it->second;

      // Restore original transaction ID
      data[0] = (pending.transaction_id >> 8) & 0xFF;
      data[1] = pending.transaction_id & 0xFF;

      // Forward response back to client
      struct pbuf *response_p = pbuf_alloc(PBUF_TRANSPORT, p->len, PBUF_RAM);
      if (response_p != nullptr) {
        memcpy(response_p->payload, data, p->len);
        udp_sendto(udp_pcb_, response_p, &pending.client_addr, pending.client_port);
        pbuf_free(response_p);

        ESP_LOGD("dns_proxy", "Forwarded response (ID: %04x -> %04x)",
                 response_id, pending.transaction_id);
      }

      // Remove from pending
      pending_queries_.erase(it);
    }
  }

  // ... parse_dns_name, parse_ip, get_reply_ip, build_dns_response remain unchanged ...
  std::string parse_dns_name(uint8_t *data, size_t len) {
    std::string name;
    size_t pos = 0;

    while (pos < len && data[pos] != 0) {
      uint8_t label_len = data[pos++];
      if (label_len > 63 || pos + label_len > len) break;

      if (!name.empty()) name += ".";
      name.append(reinterpret_cast<char*>(data + pos), label_len);
      pos += label_len;
    }

    return name;
  }

  uint32_t parse_ip(const std::string &ip_str) {
    uint32_t ip = 0;
    int parts[4] = {0};
    sscanf(ip_str.c_str(), "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
    ip = parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
    return ip;
  }

  uint32_t get_reply_ip(const std::string &query) {
    // Exact match
    auto it = records_.find(query);
    if (it != records_.end()) {
      return it->second;
    }

    // Wildcard match (*.domain.com matches sub.domain.com)
    for (const auto &record : records_) {
      if (record.first[0] == '*' && record.first[1] == '.') {
        std::string pattern = record.first.substr(2);
        if (query.size() > pattern.size() &&
            query.substr(query.size() - pattern.size()) == pattern) {
          return record.second;
        }
      }
    }

    // No match - return 0 to indicate forwarding needed
    return 0;
  }

  void build_dns_response(uint8_t *request, size_t request_len,
                          uint32_t reply_ip, std::vector<uint8_t> &response) {
    response.reserve(512);

    // Copy transaction ID
    response.push_back(request[0]);
    response.push_back(request[1]);

    // Flags: Response, Authoritative, No error
    response.push_back(0x81);
    response.push_back(0x80);

    // Question count (copy from request)
    response.push_back(request[4]);
    response.push_back(request[5]);

    // Answer count = 1
    response.push_back(0x00);
    response.push_back(0x01);

    // Authority and Additional = 0
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);

    // Copy question section
    size_t pos = 12;
    while (pos < request_len && request[pos] != 0) {
      response.push_back(request[pos++]);
    }
    if (pos < request_len) response.push_back(request[pos++]); // null terminator

    // Copy QTYPE and QCLASS (4 bytes)
    for (int i = 0; i < 4 && pos < request_len; i++) {
      response.push_back(request[pos++]);
    }

    // Answer section
    // Name pointer to question
    response.push_back(0xc0);
    response.push_back(0x0c);

    // Type A (IPv4)
    response.push_back(0x00);
    response.push_back(0x01);

    // Class IN
    response.push_back(0x00);
    response.push_back(0x01);

    // TTL (60 seconds)
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x3c);

    // Data length (4 bytes for IPv4)
    response.push_back(0x00);
    response.push_back(0x04);

    // IP address (little endian)
    response.push_back((reply_ip >> 0) & 0xFF);
    response.push_back((reply_ip >> 8) & 0xFF);
    response.push_back((reply_ip >> 16) & 0xFF);
    response.push_back((reply_ip >> 24) & 0xFF);
  }

 private:
  struct udp_pcb *udp_pcb_{nullptr};      // Server PCB (port 53)
  struct udp_pcb *client_pcb_{nullptr};   // Client PCB (for forwarding)
  std::map<std::string, uint32_t> records_;
  std::map<uint16_t, PendingQuery> pending_queries_;
  ip_addr_t upstream_dns_;
  bool has_upstream_dns_{false};

  uint32_t query_count_{0};
  uint32_t forwarded_count_{0};
  std::string last_query_;
};

}  // namespace dns_proxy
}  // namespace esphome

