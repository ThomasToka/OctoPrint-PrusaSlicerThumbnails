import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


try:
    import octoprint_e3s1proforkbyttthumbnails as plugin_module

    PluginClass = plugin_module.E3S1PROFORKBYTTThumbnailsPlugin
    IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - environment dependent
    plugin_module = None
    PluginClass = None
    IMPORT_ERROR = exc


class _Settings:
    def __init__(self):
        self.values = {"print_wait_timeout": "15"}

    def get_boolean(self, _keys):
        return False

    def get(self, keys):
        return self.values.get(keys[0])


@unittest.skipIf(IMPORT_ERROR is not None, f"plugin import unavailable: {IMPORT_ERROR}")
class PostSaveArtifactTests(unittest.TestCase):
    def setUp(self):
        self.plugin = PluginClass()
        self.plugin._logger = type("L", (), {"debug": lambda *a, **k: None, "error": lambda *a, **k: None})()
        self.plugin._settings = _Settings()
        self.plugin._file_manager = Mock()
        self.plugin._identifier = "e3s1proforkbyttthumbnails"

    def test_prime_uploaded_artifacts_marks_file_and_activates_for_immediate_print(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "storage": "local"}

        self.plugin._is_file_already_processed = Mock(return_value=False)
        self.plugin._thumbnail_output_path = Mock(return_value="/tmp/example.jpg")
        self.plugin._helper_sidecar_path = Mock(return_value="/tmp/example.gcode.thumb")
        self.plugin._cleanup_file_if_exists = Mock()
        self.plugin._extract_thumbnail = Mock()
        self.plugin._extract_transferfile = Mock(return_value=True)
        self.plugin._set_thumbnail_metadata = Mock()
        self.plugin._mark_file_processed = Mock()
        self.plugin._activate_helper_for_path = Mock()

        with (
            patch.object(plugin_module.os.path, "exists", side_effect=lambda p: p == "/tmp/example.jpg"),
            patch.object(plugin_module.flask, "has_request_context", return_value=True),
            patch.object(plugin_module.flask, "request", SimpleNamespace(values={"print": "true"})),
        ):
            self.plugin._prime_uploaded_artifacts(payload, "/uploads/prints/example.gcode")

        self.plugin._set_thumbnail_metadata.assert_called_once_with("prints/example.gcode", "/tmp/example.jpg")
        self.plugin._mark_file_processed.assert_called_once_with("prints/example.gcode")
        self.plugin._activate_helper_for_path.assert_called_once_with(
            "prints/example.gcode",
            "example.gcode",
            should_print=True,
            gcode_disk_path="/uploads/prints/example.gcode",
            trigger="file_preprocessor",
        )

    def test_prime_uploaded_artifacts_skips_when_already_processed(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "storage": "local"}

        self.plugin._is_file_already_processed = Mock(return_value=True)
        self.plugin._extract_thumbnail = Mock()
        self.plugin._extract_transferfile = Mock()
        self.plugin._mark_file_processed = Mock()

        self.plugin._prime_uploaded_artifacts(payload, "/uploads/prints/example.gcode")

        self.plugin._extract_thumbnail.assert_not_called()
        self.plugin._extract_transferfile.assert_not_called()
        self.plugin._mark_file_processed.assert_not_called()

    def test_queue_upload_processing_adds_pending_entry_once(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "storage": "local"}

        self.plugin._is_file_already_processed = Mock(return_value=False)

        queued_first = self.plugin._queue_upload_processing(payload, trigger="Upload")
        queued_second = self.plugin._queue_upload_processing(payload, trigger="Upload")

        self.assertTrue(queued_first)
        self.assertFalse(queued_second)

    def test_ensure_processed_before_print_waits_for_pending_then_returns_true(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "storage": "local"}

        self.plugin._is_file_already_processed = Mock(side_effect=[False, True])
        self.plugin._prepare_artifacts_for_payload = Mock(return_value=False)
        done_event = Mock()
        done_event.wait = Mock(return_value=True)
        self.plugin._get_pending_processing_event = Mock(return_value=done_event)

        result = self.plugin._ensure_processed_before_print(payload, trigger="PrintStarted")

        self.assertTrue(result)
        self.plugin._prepare_artifacts_for_payload.assert_not_called()

    def test_get_print_wait_timeout_clamps_and_defaults(self):
        self.plugin._settings.values["print_wait_timeout"] = "-5"
        self.assertEqual(self.plugin._get_print_wait_timeout(), 1.0)

        self.plugin._settings.values["print_wait_timeout"] = "999"
        self.assertEqual(self.plugin._get_print_wait_timeout(), 120.0)

        self.plugin._settings.values["print_wait_timeout"] = "abc"
        self.assertEqual(self.plugin._get_print_wait_timeout(), 15.0)

        self.plugin._settings.values["print_wait_timeout"] = "30"
        self.assertEqual(self.plugin._get_print_wait_timeout(), 30.0)

    def test_duplicate_helper_activation_is_suppressed(self):
        self.plugin._active_helper_inflight = False
        self.plugin._extract_transferfile = Mock(return_value=False)

        with patch.object(plugin_module.time, "monotonic", side_effect=[100.0, 101.0]):
            self.plugin._mark_helper_activation_attempt("prints/example.gcode")
            skipped = self.plugin._should_skip_duplicate_helper_activation("prints/example.gcode", "Upload")

        self.assertTrue(skipped)

    def test_queue_worker_auto_activates_when_success_and_immediate(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "print": "true"}

        self.plugin._prepare_artifacts_for_payload = Mock(return_value=True)
        self.plugin._activate_helper_for_path = Mock(return_value=True)
        self.plugin._upload_queue = Mock()
        self.plugin._upload_queue.get = Mock(return_value=payload)
        self.plugin._upload_queue.task_done = Mock()
        self.plugin._mark_processing_done = Mock()
        self.plugin._upload_worker_stop = Mock()
        self.plugin._upload_worker_stop.is_set = Mock(side_effect=[False, True])

        self.plugin._upload_processing_worker_loop()

        self.plugin._activate_helper_for_path.assert_called_once_with(
            "prints/example.gcode",
            "example.gcode",
            should_print=True,
            trigger="upload_queue",
        )


if __name__ == "__main__":
    unittest.main()
