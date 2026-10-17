# tests/comprehensive_test_suite.py
"""
Comprehensive Automated Test Suite for WiFi-Nightmare v3.0.0
Tests all modules, algorithms, data structures, and integrations.
"""
import os
import sys
import tempfile
import unittest
import struct
import json
import csv
import re

# Ensure wifi_nightmare is in path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

class TestWpsSuite(unittest.TestCase):
    """Test WPS Suite: checksum calculation, algorithmic PINs, and static databases."""

    def test_wps_checksum_calculation(self):
        from wifi_nightmare.wps_suite import calculate_wps_checksum, generate_checksum_pin
        # Official WPS test: 1234567 -> checksum is 0
        self.assertEqual(calculate_wps_checksum("1234567"), 0)
        self.assertEqual(generate_checksum_pin("1234567"), "12345670")

        # 0123456 -> checksum is 5
        self.assertEqual(calculate_wps_checksum("0123456"), 5)
        self.assertEqual(generate_checksum_pin("0123456"), "01234565")

    def test_known_pins_validity(self):
        from wifi_nightmare.wps_suite import KnownPinDatabase, calculate_wps_checksum
        mac = "00:11:22:33:44:55"
        pins = KnownPinDatabase.get_suggested_pins(mac)
        self.assertTrue(len(pins) > 0)
        for p in pins:
            self.assertEqual(len(p), 8, f"PIN {p} must be 8 digits")
            self.assertTrue(p.isdigit(), f"PIN {p} must be numeric")
            # Verify 8th digit checksum
            expected_chk = calculate_wps_checksum(p[:7])
            self.assertEqual(int(p[7]), expected_chk, f"PIN {p} has invalid checksum")

    def test_computepin_generator(self):
        from wifi_nightmare.wps_suite import KnownPinDatabase
        mac = "A0:F3:C1:2B:4E:9F"
        pins = KnownPinDatabase.get_suggested_pins(mac)
        self.assertTrue(len(pins) >= 5)


class TestPmkidAttack(unittest.TestCase):
    """Test PMKID hash generation and EAPOL parsing logic."""

    def test_hash_line_format(self):
        from wifi_nightmare.pmkid_attack import build_pmkid_hash_line
        ssid = "TestNetwork"
        bssid = "aa:bb:cc:dd:ee:ff"
        client = "11:22:33:44:55:66"
        pmkid = "0123456789abcdef0123456789abcdef"
        line = build_pmkid_hash_line(ssid, bssid, client, pmkid)
        self.assertTrue(line.startswith("WPA*01*"))
        parts = line.split("*")
        self.assertEqual(parts[1], "01")
        self.assertEqual(parts[2], pmkid)
        self.assertEqual(parts[3], "aabbccddeeff")
        self.assertEqual(parts[4], "112233445566")
        self.assertEqual(parts[5], ssid.encode().hex())

    def test_eapol_pmkid_extraction(self):
        from wifi_nightmare.pmkid_attack import PMKIDAttack
        attacker = PMKIDAttack("wlan0", "aa:bb:cc:dd:ee:ff", 6, "TestNet")
        
        # Build synthetic EAPOL frame with PMKID KDE (OUI 00:0f:ac, type 4)
        expected_pmkid = bytes.fromhex("11223344556677889900aabbccddeeff")
        # KDE header: 0xdd, length, OUI (3 bytes), Data Type (1 byte), PMKID (16 bytes)
        kde = bytes([0xdd, 20]) + b'\x00\x0f\xac\x04' + expected_pmkid
        # Prepend dummy EAPOL header (97 bytes) + key_data_length (2 bytes)
        fake_header = b'\x00' * 97
        fake_payload = fake_header + struct.pack('!H', len(kde)) + kde
        
        extracted = attacker._extract_pmkid_from_eapol(fake_payload)
        self.assertEqual(extracted, expected_pmkid.hex())


class TestWordlistManager(unittest.TestCase):
    """Test smart wordlist generation, vendor defaults, and WPA length rules."""

    def test_ssid_variations(self):
        from wifi_nightmare.wordlist_manager import WordlistManager
        wm = WordlistManager()
        words = wm.generate_ssid_wordlist("HomeNet", "00:11:22:33:44:55")
        self.assertTrue(len(words) > 0)
        # All words must be valid WPA length (8-63)
        for w in words:
            self.assertTrue(8 <= len(w) <= 63, f"Invalid length for password: {w}")
        # Must contain obvious variations
        self.assertIn("HomeNet123", words)

    def test_vendor_patterns_mena(self):
        from wifi_nightmare.wordlist_manager import WordlistManager
        wm = WordlistManager()
        # WE / TE-Data
        we_words = wm.get_vendor_defaults("WE_Fiber_4G")
        self.assertTrue(len(we_words) > 0)
        # Vodafone
        vf_words = wm.get_vendor_defaults("Vodafone-Home")
        self.assertTrue(len(vf_words) > 0)
        # Orange
        org_words = wm.get_vendor_defaults("Orange_WiFi_12")
        self.assertTrue(len(org_words) > 0)
        # TP-Link
        tp_words = wm.get_vendor_defaults("TP-Link_9A4F")
        self.assertTrue(len(tp_words) > 0)


class TestSessionExporter(unittest.TestCase):
    """Test JSON, CSV, and text session export."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def test_json_and_csv_export(self):
        from wifi_nightmare.session_export import SessionExporter
        exporter = SessionExporter(export_dir=self.temp_dir)
        mock_networks = {
            "aa:bb:cc:dd:ee:ff": {
                "SSID": "CorpNetwork",
                "Channel": 6,
                "RSSI": -55,
                "Crypto": "WPA2 CCMP",
                "WPS": True,
                "Hidden": False,
                "Vendor": "Cisco",
                "Clients": ["11:22:33:44:55:66"],
            },
            "11:22:33:44:55:66": {
                "SSID": "GuestNet",
                "Channel": 1,
                "RSSI": -75,
                "Crypto": "WPA3/SAE",
                "WPS": False,
                "Hidden": True,
                "Vendor": "Aruba",
                "Clients": [],
            }
        }
        
        # Test JSON
        json_file = exporter.export_json(mock_networks, interface="wlan0mon")
        self.assertTrue(os.path.exists(json_file))
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertEqual(data['summary']['total_networks'], 2)
            self.assertEqual(data['summary']['wpa3_networks'], 1)
            self.assertEqual(data['summary']['hidden_networks'], 1)

        # Test CSV
        csv_file = exporter.export_csv(mock_networks)
        self.assertTrue(os.path.exists(csv_file))
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 2)
            self.assertEqual(reader[0]['ssid'], "CorpNetwork")

        # Test Text Report
        txt_file = exporter.export_text_report(mock_networks, interface="wlan0mon")
        self.assertTrue(os.path.exists(txt_file))
        with open(txt_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("WiFi-Nightmare", content)
            self.assertIn("CorpNetwork", content)


class TestGeoLookup(unittest.TestCase):
    """Test Geo-Location caching and result formatting."""

    def setUp(self):
        self.temp_file = tempfile.mktemp(suffix=".json")

    def test_geo_cache_and_url(self):
        from wifi_nightmare.geo_lookup import GeoCache, GeoResult
        cache = GeoCache(cache_file=self.temp_file)
        
        result = GeoResult(
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="CoffeeShop",
            lat=30.0444,
            lon=31.2357,
            accuracy=25.0,
            city="Cairo",
            country="Egypt",
            provider="openwifi",
            found=True
        )
        self.assertIn("30.0444", result.google_maps_url)
        self.assertIn("31.2357", result.google_maps_url)

        # Write & Read Cache
        cache.set("aa:bb:cc:dd:ee:ff", result.__dict__)
        cached = cache.get("aa:bb:cc:dd:ee:ff")
        self.assertIsNotNone(cached)
        self.assertEqual(cached['city'], "Cairo")


class TestCardManager(unittest.TestCase):
    """Test multi-card adapter role assignments."""

    def test_single_and_dual_card_logic(self):
        from wifi_nightmare.card_manager import CardManager, WirelessAdapter
        cm = CardManager()
        
        # Test empty/single
        roles_single = cm.auto_assign_roles(preferred_iface="wlan0")
        self.assertIn(roles_single['mode'], ["single", "dual"])

        # Manually populate adapters to test dual role division
        cm.adapters = [
            WirelessAdapter(name="wlan0", phy="phy0", driver="ath9k_htc", chipset="AR9271"),
            WirelessAdapter(name="wlan1", phy="phy1", driver="rtl8812au", chipset="RTL8812AU"),
        ]
        roles_dual = cm.auto_assign_roles(preferred_iface="wlan0", refresh=False)
        self.assertEqual(roles_dual['mode'], "dual")
        self.assertEqual(roles_dual['sniffer'], "wlan0")
        self.assertEqual(roles_dual['injector'], "wlan1")


class TestFakeRadius(unittest.TestCase):
    """Test RADIUS packet parsing and Access-Accept building."""

    def test_radius_packet_parsing_and_accept(self):
        from wifi_nightmare.radius_fake import RADIUSPacket, RADIUS_ACCESS_REQUEST, ATTR_USER_NAME
        
        # Build raw RADIUS Access-Request
        user_bytes = b"admin@corp.local"
        attr_payload = bytes([ATTR_USER_NAME, len(user_bytes) + 2]) + user_bytes
        total_len = 20 + len(attr_payload)
        auth = b'\x12' * 16
        raw_req = bytes([RADIUS_ACCESS_REQUEST, 42, (total_len >> 8) & 0xff, total_len & 0xff]) + auth + attr_payload

        pkt = RADIUSPacket(raw_req)
        self.assertEqual(pkt.code, RADIUS_ACCESS_REQUEST)
        self.assertEqual(pkt.identifier, 42)
        self.assertEqual(pkt.get_username(), "admin@corp.local")

        # Test Access-Accept response
        accept_pkt = RADIUSPacket.build_accept(pkt.identifier, pkt.authenticator)
        parsed_accept = RADIUSPacket(accept_pkt)
        self.assertEqual(parsed_accept.code, 2)  # RADIUS_ACCESS_ACCEPT
        self.assertEqual(parsed_accept.identifier, 42)


class TestBeaconFlood(unittest.TestCase):
    """Test random MAC generation and SSID modes."""

    def test_random_mac(self):
        from wifi_nightmare.beacon_flood import _random_mac
        for _ in range(10):
            mac = _random_mac()
            parts = mac.split(':')
            self.assertEqual(len(parts), 6)
            first_byte = int(parts[0], 16)
            # Must be unicast (LSB of byte 0 is 0) and locally administered (bit 1 is 1)
            self.assertEqual(first_byte & 0x01, 0, "MAC must be unicast")
            self.assertEqual(first_byte & 0x02, 2, "MAC must be locally administered")


class TestUiGridRendering(unittest.TestCase):
    """Test ANSI strip, padding, and menu rendering."""

    def test_strip_ansi_and_pad(self):
        from wifi_nightmare.ui import strip_ansi, pad_visible
        colored_text = "\033[1;32mHello\033[0m"
        self.assertEqual(strip_ansi(colored_text), "Hello")
        
        padded = pad_visible(colored_text, 10)
        self.assertEqual(len(strip_ansi(padded)), 10)

    def test_menus_render_without_exception(self):
        from wifi_nightmare.ui import (
            print_main_menu, print_target_menu, print_database_menu, print_portal_menu
        )
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            print_main_menu("wlan0mon", "Connected", "Supported")
            print_target_menu("TestNet", "aa:bb:cc:dd:ee:ff", 6, 2, "WPA2", "TP-Link", True, True, True)
            print_database_menu()
            print_portal_menu(["WE_Fiber", "Vodafone"], "Default")
        
        output = f.getvalue()
        self.assertIn("Scan & Reconnaissance", output)
        self.assertIn("Capture Handshake", output)
        self.assertIn("TARGET AUDIT WORKSPACE", output)
        self.assertIn("List Saved Networks", output)

    def test_menu_centering_layout(self):
        from wifi_nightmare.ui import get_menu_layout, get_menu_margin
        from unittest.mock import patch
        import collections

        term_size = collections.namedtuple('terminal_size', ['columns', 'lines'])
        
        # Test wide terminal (160 cols) -> 108 block with 26 margin
        with patch('shutil.get_terminal_size', return_value=term_size(160, 40)):
            block_w, margin = get_menu_layout()
            self.assertEqual(block_w, 108)
            self.assertEqual(margin, 26)
            self.assertEqual(get_menu_margin(), 26)

        # Test standard terminal (120 cols) -> 108 block with 6 margin
        with patch('shutil.get_terminal_size', return_value=term_size(120, 40)):
            block_w, margin = get_menu_layout()
            self.assertEqual(block_w, 108)
            self.assertEqual(margin, 6)

        # Test compact terminal (80 cols) -> single column, centered
        with patch('shutil.get_terminal_size', return_value=term_size(80, 24)):
            block_w, margin = get_menu_layout()
            self.assertEqual(block_w, 56)
            self.assertEqual(margin, 12)


class TestMainOrchestrator(unittest.TestCase):
    """Verify WifiGTR class has all attack methods wired up."""

    def test_wifigtr_methods_exist(self):
        from wifi_nightmare.main import WifiGTR
        expected_methods = [
            "run_pmkid_attack",
            "run_karma_attack",
            "run_beacon_flood",
            "run_wpa_enterprise",
            "run_smart_crack",
            "run_wpa3_downgrade",
            "run_aircrack_crack",
            "run_software_eviltwin",
            "run_pixie_dust_workflow",
            "run_multivector_eviction",
            "scan_workflow",
            "main_loop",
        ]
        for m in expected_methods:
            self.assertTrue(hasattr(WifiGTR, m), f"WifiGTR is missing method: {m}")


class TestDatabaseHandler(unittest.TestCase):
    """Test JSON database storage, network saves, handshake tracking, and WPS info."""

    def setUp(self):
        self.temp_db = tempfile.mktemp(suffix=".json")

    def tearDown(self):
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)

    def test_database_crud(self):
        from wifi_nightmare.database import DatabaseHandler
        db = DatabaseHandler(db_file=self.temp_db)
        
        # Save network
        db.save("aa:bb:cc:dd:ee:ff", "OfficeNet")
        info = db.get_info("aa:bb:cc:dd:ee:ff")
        self.assertEqual(info['SSID'], "OfficeNet")
        self.assertFalse(info['Handshake'])

        # Update handshake
        db.update_handshake("aa:bb:cc:dd:ee:ff", True, "12:00 PM", "hs.cap")
        info = db.get_info("aa:bb:cc:dd:ee:ff")
        self.assertTrue(info['Handshake'])
        self.assertEqual(info['HSFile'], "hs.cap")

        # Update WPS info
        db.update_wps_info("aa:bb:cc:dd:ee:ff", "12345670", "secretpass123")
        info = db.get_info("aa:bb:cc:dd:ee:ff")
        self.assertEqual(info['WPS_PIN'], "12345670")
        self.assertEqual(info['WPS_PSK'], "secretpass123")


class TestUtilsAndPrivacy(unittest.TestCase):
    """Test MAC address masking, filename sanitization, and time utilities."""

    def test_mask_bssid(self):
        from wifi_nightmare.utils import mask_bssid, mask_bssid_filename, scrub_bssid
        mac = "00:11:22:33:44:55"
        masked = mask_bssid(mac)
        self.assertEqual(masked, "00:xx:xx:xx:xx:55")

        masked_fn = mask_bssid_filename(mac)
        self.assertEqual(masked_fn, "00-xx-xx-xx-xx-55")

        cmd = "aircrack-ng -b 00:11:22:33:44:55 capture.cap"
        scrubbed = scrub_bssid(cmd, mac)
        self.assertNotIn("00:11:22:33:44:55", scrubbed)
        self.assertIn("00:xx:xx:xx:xx:55", scrubbed)

    def test_safe_ssid(self):
        from wifi_nightmare.utils import safe_ssid
        self.assertEqual(safe_ssid("My WiFi / 5G & More!"), "My WiFi  5G  More")
        self.assertEqual(safe_ssid(""), "Unknown_SSID")
        self.assertEqual(safe_ssid("<HIDDEN>"), "Unknown_SSID")


if __name__ == '__main__':
    unittest.main(verbosity=2)
