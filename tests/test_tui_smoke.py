import unittest
from pathlib import Path
from unittest import mock

from textual.css.stylesheet import Stylesheet
from textual.widgets import ContentSwitcher

from netpal.textual_ui.theme import APP_CSS as INTERNAL_APP_CSS
from netpal.tui import (
    APP_CSS,
    DetailPane,
    MetricStrip,
    NetPalApp,
    ProjectsView,
    TextAction,
    VIEW_PROJECTS,
)


class TUIStylesheetSmokeTests(unittest.TestCase):
    def test_public_css_is_loaded_from_internal_theme_file(self):
        self.assertEqual(APP_CSS, INTERNAL_APP_CSS)
        theme_path = Path("netpal/textual_ui/styles.tcss")
        self.assertEqual(APP_CSS, theme_path.read_text(encoding="utf-8"))

    def test_textual_stylesheet_parser_accepts_app_css(self):
        stylesheet = Stylesheet()
        stylesheet.add_source(APP_CSS, "netpal/textual_ui/styles.tcss")
        stylesheet.parse()
        self.assertTrue(stylesheet.rules)


class TUIAppStartupSmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_app_mounts_with_project_view_and_top_nav(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(120, 40)):
                switcher = app.query_one("#main-switcher", ContentSwitcher)
                self.assertEqual(switcher.current, VIEW_PROJECTS)
                self.assertEqual(app.query_one("#nav-view-projects", TextAction).label, "Projects")
                self.assertIsNotNone(app.query_one(ProjectsView).query_one(MetricStrip))
                self.assertIsNotNone(app.query_one(ProjectsView).query_one(DetailPane))

    async def test_app_mounts_in_narrow_layout_with_compact_nav_labels(self):
        with mock.patch("netpal.textual_ui.app._list_projects", return_value=[]):
            app = NetPalApp()
            app.config["project_name"] = ""

            async with app.run_test(size=(83, 40)) as pilot:
                await pilot.pause()
                self.assertTrue(app.has_class("layout-narrow"))
                self.assertEqual(app.query_one("#nav-view-projects", TextAction).label, "Proj")
                self.assertEqual(app.query_one("#nav-view-findings", TextAction).label, "Find")


if __name__ == "__main__":
    unittest.main()
