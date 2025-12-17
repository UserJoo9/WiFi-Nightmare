#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

// هيكل رأس MAC (متوافق مع ESP8266)
typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t sequence_ctrl;
} mac_hdr_t;

// هيكل حزمة الواي فاي
typedef struct {
    mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_packet_t;

// هيكل إطار deauth (مبسط للإرسال عبر ESP8266)
typedef struct {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t destination[6];
    uint8_t source[6];
    uint8_t bssid[6];
    uint16_t seq;
    uint16_t reason;
} deauth_frame_t;

// هيكل حزمة الواي فاي في وضع المراقبة (لـ ESP8266)
typedef struct {
    // rx_ctrl field structure for ESP8266
    signed rssi: 8;
    unsigned rate: 4;
    unsigned is_group: 1;
    unsigned: 1;
    unsigned sig_mode: 2;
    unsigned legacy_length: 12;
    unsigned damatch0: 1;
    unsigned damatch1: 1;
    unsigned bssidmatch0: 1;
    unsigned bssidmatch1: 1;
    unsigned mcs: 7;
    unsigned cwb: 1;
    unsigned: 16;
    unsigned: 16;
    unsigned: 16;
    unsigned: 16;
    
    uint8_t payload[0];
} wifi_promiscuous_pkt_t;

#endif