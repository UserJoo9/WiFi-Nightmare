#include <Arduino.h>
#include <ESP8266WiFi.h>
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

  // FIX: Lower TX Power (10dBm)
  WiFi.setOutputPower(10);

  serial_cmd_init();
}

void loop()
{
  serial_cmd_handle();
}