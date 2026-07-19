#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "definitions.h"
#include "serial_handler.h"

void setup()
{
  Serial.begin(115200);

#ifdef LED
  pinMode(LED, OUTPUT);
  digitalWrite(LED, LOW);
#endif

  // وضع STA ضروري للحقن
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  // FIX: Lower TX Power to prevent Brownout (10dBm)
  esp_wifi_set_max_tx_power(40);

  serial_cmd_init();
}

void loop()
{
  serial_cmd_handle();
}