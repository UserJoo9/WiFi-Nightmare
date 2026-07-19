#ifndef DEAUTH_H
#define DEAUTH_H
#include "types.h"
#include <Arduino.h>

void start_deauth(int wifi_number, int attack_type, uint16_t reason);
void stop_deauth();

extern int eliminated_stations;
extern int deauth_type;

extern deauth_frame_t deauth_frame;
// تعريف دالة الإرسال الخام لكي نستخدمها في الملف الجديد
extern "C" esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

#endif