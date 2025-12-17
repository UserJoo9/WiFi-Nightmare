#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define AP_SSID "ooo"
#define AP_PASS "12345678"
#define LED 2  // Built-in LED on NodeMCU
#define SERIAL_DEBUG
#define CHANNEL_MAX 13
#define NUM_FRAMES_PER_DEAUTH 16
#define DEAUTH_BLINK_TIMES 2
#define DEAUTH_BLINK_DURATION 20
#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL 1

#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...) Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

#ifdef LED
void blink_led(int num_times, int blink_duration);
#define BLINK_LED(num_times, blink_duration) blink_led(num_times, blink_duration)
#else
#define BLINK_LED(num_times, blink_duration)
#endif

#endif