import unittest


try:
    import octoprint_e3s1proforkbyttthumbnails as plugin_module

    PluginClass = plugin_module.E3S1PROFORKBYTTThumbnailsPlugin
    IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - environment dependent
    plugin_module = None
    PluginClass = None
    IMPORT_ERROR = exc


@unittest.skipIf(IMPORT_ERROR is not None, f"plugin import unavailable: {IMPORT_ERROR}")
class UploadIntentAndPayloadTests(unittest.TestCase):
    def setUp(self):
        self.plugin = PluginClass()
        self.plugin._logger = type("L", (), {"debug": lambda *a, **k: None})()

    def test_immediate_select_or_print_supports_snake_case(self):
        payload = {"effective_print": "true"}

        self.assertTrue(self.plugin._wants_immediate_select_or_print(payload))
        self.assertTrue(self.plugin._wants_immediate_print(payload))

    def test_immediate_select_or_print_supports_camel_case_bool(self):
        payload = {"effectiveSelect": True, "effectivePrint": False}

        self.assertTrue(self.plugin._wants_immediate_select_or_print(payload))
        self.assertFalse(self.plugin._wants_immediate_print(payload))

    def test_normalize_payload_accepts_nested_file_payload(self):
        payload = {
            "file": {"path": "prints/example.gcode", "name": "example.gcode"},
            "origin": "local",
        }

        normalized = self.plugin._normalize_local_payload(payload, trigger="test")

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["path"], "prints/example.gcode")
        self.assertEqual(normalized["name"], "example.gcode")
        self.assertEqual(normalized["storage"], "local")

    def test_normalize_payload_rejects_non_local_storage(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "storage": "sdcard"}

        self.assertIsNone(self.plugin._normalize_local_payload(payload, trigger="test"))

    def test_upload_event_queues_when_inline_prepare_fails(self):
        payload = {"path": "prints/example.gcode", "name": "example.gcode", "storage": "local"}

        self.plugin._prepare_artifacts_for_payload = lambda *_a, **_k: False
        queued = {"value": False}

        def _queue(*_a, **_k):
            queued["value"] = True
            return True

        self.plugin._queue_upload_processing = _queue
        self.plugin._wants_immediate_select_or_print = lambda *_a, **_k: False

        self.plugin.on_event("Upload", payload)

        self.assertTrue(queued["value"])


if __name__ == "__main__":
    unittest.main()
