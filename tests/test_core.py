import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from WiFiNightmare.database import DatabaseHandler
from WiFiNightmare.config import DB_FILE


class TestDatabaseHandler(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseHandler()
        self.test_bssid = "AA:BB:CC:DD:EE:FF"
        self.test_ssid = "TestNetwork"

    def tearDown(self):
        if self.test_bssid.lower() in self.db.known_networks:
            del self.db.known_networks[self.test_bssid.lower()]
            self.db._write_to_file()

    def test_save_and_get(self):
        self.db.save(self.test_bssid, self.test_ssid)
        info = self.db.get_info(self.test_bssid)
        self.assertIsNotNone(info)
        self.assertEqual(info['SSID'], self.test_ssid)
        self.assertFalse(info['Handshake'])

    def test_invalid_bssid_rejected(self):
        self.db.save("invalid-mac", self.test_ssid)
        self.assertIsNone(self.db.get_info("invalid-mac"))

    def test_update_handshake(self):
        self.db.save(self.test_bssid, self.test_ssid)
        self.db.update_handshake(self.test_bssid, True, "12:00 PM", "/path/to/file.pcap")
        info = self.db.get_info(self.test_bssid)
        self.assertTrue(info['Handshake'])
        self.assertEqual(info['HSFile'], "/path/to/file.pcap")

    def test_get_info_unknown(self):
        result = self.db.get_info("FF:FF:FF:FF:FF:FF")
        self.assertIsNone(result)

    def test_bssid_case_insensitive(self):
        self.db.save(self.test_bssid, self.test_ssid)
        info = self.db.get_info("aa:bb:cc:dd:ee:ff")
        self.assertIsNotNone(info)
        self.assertEqual(info['SSID'], self.test_ssid)


class TestVendorLookup(unittest.TestCase):
    def test_known_vendor(self):
        from WiFiNightmare.vendors import INTERNAL_DB
        self.assertIn("00:03:93", INTERNAL_DB)
        self.assertEqual(INTERNAL_DB["00:03:93"], "Apple")

    def test_invalid_mac_returns_unknown(self):
        from WiFiNightmare.vendors import lookup_vendor
        self.assertEqual(lookup_vendor(""), "Unknown")
        self.assertEqual(lookup_vendor(None), "Unknown")
        self.assertEqual(lookup_vendor("XX"), "Unknown")

    def test_internal_db_hit(self):
        from WiFiNightmare.vendors import lookup_vendor
        result = lookup_vendor("00:03:93:AA:BB:CC")
        self.assertEqual(result, "Apple")


class TestConfig(unittest.TestCase):
    def test_config_loads(self):
        from WiFiNightmare.config import config
        self.assertIn('scanning', config)
        self.assertIn('attacks', config)
        self.assertIn('database', config)
        self.assertIn('esp32', config)
        self.assertIn('output', config)

    def test_colors_defined(self):
        from WiFiNightmare.config import C_GREEN, C_RED, C_YELLOW, C_RESET
        self.assertIn("\033", C_GREEN)
        self.assertIn("\033", C_RED)
        self.assertIn("\033", C_YELLOW)
        self.assertIn("\033", C_RESET)


class TestSignalManager(unittest.TestCase):
    def test_context_manager(self):
        from WiFiNightmare.utils import SignalManager
        with SignalManager() as sig:
            self.assertFalse(sig.stopped)

    def test_stop(self):
        from WiFiNightmare.utils import SignalManager
        with SignalManager() as sig:
            sig.stop()
            self.assertTrue(sig.stopped)


if __name__ == '__main__':
    unittest.main()
