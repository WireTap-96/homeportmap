import unittest
from unittest.mock import patch
from homeportmap.cli import scan, validate_network, probe

class HomePortMapTests(unittest.TestCase):
    def test_accepts_small_private_subnet(self):
        self.assertEqual(str(validate_network("192.168.1.0/28")), "192.168.1.0/28")

    def test_rejects_public_and_broad_ranges(self):
        for cidr in ("8.8.8.0/24", "10.0.0.0/8", "192.168.0.0/16"):
            with self.subTest(cidr=cidr), self.assertRaises(ValueError):
                validate_network(cidr)

    def test_scan_uses_fixed_ports_and_limited_pool(self):
        with patch("homeportmap.cli.probe", return_value=False) as mocked:
            result = scan("192.168.1.0/30")
        self.assertEqual(result["hosts_checked"], 2)
        self.assertEqual(result["hosts_with_open_ports"], 0)
        self.assertEqual(mocked.call_count, 20)

    def test_probe_reports_open_socket(self):
        with patch("homeportmap.cli.socket.create_connection") as mocked:
            self.assertTrue(probe("192.168.1.5", 80))
            mocked.assert_called_once()

if __name__ == "__main__":
    unittest.main()
