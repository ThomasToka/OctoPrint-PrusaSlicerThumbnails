import unittest
from unittest.mock import Mock, patch


try:
    import octoprint_e3s1proforkbyttthumbnails as plugin_module

    PluginClass = plugin_module.E3S1PROFORKBYTTThumbnailsPlugin
    IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - environment dependent
    plugin_module = None
    PluginClass = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, f"plugin import unavailable: {IMPORT_ERROR}")
class TransferDoneFlowTests(unittest.TestCase):
    def setUp(self):
        self.plugin = PluginClass()
        self.plugin._logger = type("L", (), {"debug": lambda *a, **k: None, "error": lambda *a, **k: None})()
        self.plugin._file_manager = Mock()
        self.plugin._printer = Mock()
        self.plugin.get_plugin_data_folder = Mock(return_value="/plugin-data")
        self.plugin.selectedPrintFilename = "example.gcode"
        self.plugin.selectedPrintFolderRel = "prints"
        self.plugin._active_helper_inflight = True

    def test_transfer_done_starts_delayed_print_when_requested(self):
        self.plugin._post_helper_should_print = True
        self.plugin._post_helper_file_rel_path = "prints/example.gcode"
        self.plugin._purge_uploads_helper = Mock()
        self.plugin._start_print_after_helper_transfer = Mock()
        self.plugin._file_manager.path_on_disk.return_value = "/uploads/prints/example.gcode"

        with patch.object(plugin_module.os.path, "exists", return_value=False):
            self.plugin.on_event("TransferDone", {"local": "OCTODGUS.GCO"})

        self.plugin._printer.select_file.assert_called_once_with("/uploads/prints/example.gcode", False, False)
        self.plugin._start_print_after_helper_transfer.assert_called_once_with("prints/example.gcode")
        self.assertFalse(self.plugin._active_helper_inflight)

    def test_transfer_done_does_not_start_delayed_print_when_not_requested(self):
        self.plugin._post_helper_should_print = False
        self.plugin._post_helper_file_rel_path = "prints/example.gcode"
        self.plugin._purge_uploads_helper = Mock()
        self.plugin._start_print_after_helper_transfer = Mock()
        self.plugin._file_manager.path_on_disk.return_value = "/uploads/prints/example.gcode"

        with patch.object(plugin_module.os.path, "exists", return_value=False):
            self.plugin.on_event("TransferDone", {"local": "OCTODGUS.GCO"})

        self.plugin._printer.select_file.assert_called_once_with("/uploads/prints/example.gcode", False, False)
        self.plugin._start_print_after_helper_transfer.assert_not_called()
        self.assertFalse(self.plugin._active_helper_inflight)


if __name__ == "__main__":
    unittest.main()
