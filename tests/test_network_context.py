import unittest
from unittest import mock

from netpal.models.host import Host
from netpal.models.project import Project
from netpal.models.service import Service
from netpal.utils.network_context import detect_network_context


class NetworkContextTests(unittest.TestCase):
    def test_detect_network_context_uses_default_gateway_identity(self):
        with (
            mock.patch("netpal.utils.network_context._get_default_gateway_ip", return_value="10.0.0.1"),
            mock.patch("netpal.utils.network_context._get_wifi_ssid", return_value="CorpWiFi"),
            mock.patch("netpal.utils.network_context._get_wifi_bssid", return_value="aa:bb:cc:dd:ee:ff"),
        ):
            context = detect_network_context("wlan0")

        self.assertEqual(context.network_id, "gateway:10.0.0.1")
        self.assertEqual(context.label, "CorpWiFi (10.0.0.1)")
        self.assertEqual(
            context.details,
            {"gateway_ip": "10.0.0.1", "ssid": "CorpWiFi", "interface": "wlan0"},
        )

    def test_detect_network_context_falls_back_to_wifi_identity_without_gateway(self):
        with (
            mock.patch("netpal.utils.network_context._get_default_gateway_ip", return_value=None),
            mock.patch("netpal.utils.network_context._get_wifi_ssid", return_value="CorpWiFi"),
            mock.patch("netpal.utils.network_context._get_wifi_bssid", return_value="aa:bb:cc:dd:ee:ff"),
        ):
            context = detect_network_context("wlan0")

        self.assertEqual(context.network_id, "wifi:aa:bb:cc:dd:ee:ff/CorpWiFi")
        self.assertEqual(context.label, "CorpWiFi (aa:bb:cc:dd:ee:ff)")

    def test_project_merges_hosts_when_gateway_identity_matches(self):
        project = Project(name="Gateway Identity")

        project.add_host(
            Host(
                "10.0.0.253",
                network_id="gateway:10.0.0.1",
                services=[Service(80)],
            )
        )
        project.add_host(
            Host(
                "10.0.0.253",
                network_id="gateway:10.0.0.1",
                services=[Service(443)],
            )
        )
        project.add_host(
            Host(
                "10.0.0.253",
                network_id="gateway:10.0.10.1",
                services=[Service(22)],
            )
        )

        self.assertEqual(len(project.hosts), 2)
        merged = project.get_host_by_identity("10.0.0.253", "gateway:10.0.0.1")
        self.assertIsNotNone(merged)
        self.assertEqual(sorted(service.port for service in merged.services), [80, 443])


if __name__ == "__main__":
    unittest.main()
