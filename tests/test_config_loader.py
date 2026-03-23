import json
import os
import tempfile
import unittest
from unittest import mock

from netpal.utils.config_loader import ConfigLoader


class ConfigLoaderTests(unittest.TestCase):
    def test_load_auto_tool_credentials_bootstraps_creds_from_example(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_path = os.path.join(tmpdir, "creds.json")
            creds_example_path = os.path.join(tmpdir, "creds.json.example")
            example_data = [
                {
                    "username": "CORP\\tester",
                    "password": "P@ssw0rd!",
                    "type": "domain",
                    "use_in_auto_tools": False,
                }
            ]

            with open(creds_example_path, "w", encoding="utf-8") as fh:
                json.dump(example_data, fh, indent=2)

            def _fake_get_config_path(filename):
                mapping = {
                    "creds.json": creds_path,
                    "creds.json.example": creds_example_path,
                }
                return mapping[filename]

            with mock.patch.object(ConfigLoader, "get_config_path", side_effect=_fake_get_config_path):
                loaded = ConfigLoader.load_auto_tool_credentials()

            self.assertEqual(loaded, example_data)
            self.assertTrue(os.path.exists(creds_path))
            with open(creds_path, "r", encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), example_data)


if __name__ == "__main__":
    unittest.main()
