"""Actual telemetry entry and transport proof using a secretless HTTP peer."""

import contextlib
import copy
from datetime import datetime
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/coordinator-deploy.yml"
BASELINE_REVISION = "782d1e5be239862da3dcdb3502875190794b43fb"
# One local immutable source read; no credentials, downloads, or executable fixtures.
BASELINE = subprocess.check_output(
    ["git", "show", BASELINE_REVISION + ":.github/workflows/coordinator-deploy.yml"], cwd=ROOT, text=True,
)


def load(text):
    shell = "\n".join(line[10:] for line in text.split("        run: |\n", 1)[1].splitlines()) + "\n"
    source = shell.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
    module = types.ModuleType("telemetry_diagnostic")
    exec(compile(source, str(WORKFLOW), "exec"), module.__dict__)
    return module


MODULE = load(WORKFLOW.read_text())
OLD = load(BASELINE)
TOKEN = "synthetic-private-token"
PRIVATE = "synthetic-private-response"
VERSION = "11111111-1111-4111-8111-111111111111"
DO_ID = "b" * 64
REQUEST_ID = "c" * 16
BASE = "https://api.cloudflare.com/client/v4/accounts/91b59577e757131d68d55a471fe32aca/workers"
SETTINGS = "/scripts/crabbox-coordinator/settings"
TELEMETRY = "/observability/telemetry/query"
FROM = int(datetime.fromisoformat("2026-10-12T00:24:00+00:00").timestamp() * 1000)
TO = int(datetime.fromisoformat("2026-10-12T00:31:00+00:00").timestamp() * 1000)
EXPECTED_QUERY = {
    "queryId": "coordinator-failure-20261012", "dry": True,
    "timeframe": {"from": FROM, "to": TO}, "view": "events", "limit": 200,
    "parameters": {"filters": [{"key": "$workers.scriptName", "operation": "eq",
                                "type": "string", "value": "crabbox-coordinator"}]},
}
ENV = {
    "GITHUB_REPOSITORY": "openclaw/crabbox", "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/ops/capacity-settings-20261011",
    "GITHUB_WORKFLOW_REF": "openclaw/crabbox/.github/workflows/coordinator-deploy.yml@refs/heads/ops/capacity-settings-20261011",
    "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
    "GITHUB_RUN_ATTEMPT": "1", "CLOUDFLARE_API_TOKEN": TOKEN,
}


def forbid_external(event, args):
    if event.startswith(("socket.", "subprocess.", "ctypes.")) or event in {
        "os.system", "os.fork", "os.exec", "os.posix_spawn"
    }:
        raise AssertionError("external_execution_forbidden")


sys.addaudithook(forbid_external)


class Response(io.BytesIO):
    status = 200


class HTTPPeer:
    def __init__(self):
        self.requests = []
        self.http_error = None
        self.api_errors = []
        self.raw = None
        self.settings = {"bindings": [{"name": "CRABBOX_MAX_ACTIVE_LEASES_PER_OWNER", "type": "plain_text", "text": "10"},
                                      {"name": "PRIVATE", "type": "secret_text", "text": TOKEN}], "annotations": {"workers/message": PRIVATE}}
        self.events = [{"timestamp": FROM + 12000, "$metadata": {"error": "TypeError: " + PRIVATE,
                        "statusCode": 500, "url": TOKEN}, "source": {
                            "name": "TypeError", "message": PRIVATE,
                            "stack": "TypeError: " + PRIVATE + "\n    at secretFunction (src/fleet.ts:4335:12)\n    at index.js:900:3\n    at https://private.invalid/secret.js:1:2",
                            "token": TOKEN, "args": [PRIVATE, TOKEN]}, "$workers": {
                            "scriptName": "crabbox-coordinator", "scriptVersion": {"id": VERSION, "tag": TOKEN},
                            "requestId": REQUEST_ID, "durableObjectId": DO_ID, "outcome": "exception",
                            "event": {"request": {"headers": {"Authorization": TOKEN}}}}}]

    def open(self, request, timeout):
        assert timeout == 30
        assert request.get_header("Authorization") == "Bearer " + TOKEN
        route = (request.get_method(), request.full_url)
        self.requests.append(route)
        assert route == [("GET", BASE + SETTINGS), ("POST", BASE + TELEMETRY)][len(self.requests) - 1]
        if request.get_method() == "GET":
            assert request.data is None
            return Response(json.dumps({"success": True, "errors": [], "result": self.settings}).encode())
        assert request.get_header("Content-type") == "application/json"
        assert json.loads(request.data) == EXPECTED_QUERY
        if self.http_error:
            raise urllib.error.HTTPError(request.full_url, self.http_error, PRIVATE,
                                         {"Location": "https://private.invalid"}, io.BytesIO(self.raw or json.dumps({
                                             "success": False, "errors": self.api_errors, "message": TOKEN,
                                         }).encode()))
        return Response(self.raw if self.raw is not None else json.dumps({
            "success": not self.api_errors, "errors": self.api_errors,
            "result": {"events": {"events": self.events}},
        }).encode())


class TelemetryTests(unittest.TestCase):
    def invoke(self, peer, env=None):
        output = io.StringIO()
        def opener(*handlers):
            self.assertEqual(len(handlers), 1)
            self.assertIsInstance(handlers[0], MODULE.NoRedirect)
            self.assertIsNone(handlers[0].redirect_request(None, None, 302, PRIVATE, {}, "https://elsewhere.invalid"))
            return peer
        with patch.dict(os.environ, ENV if env is None else env, clear=True), \
             patch.object(MODULE.urllib.request, "build_opener", side_effect=opener), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = MODULE.main()
        raw = output.getvalue()
        for forbidden in (TOKEN, PRIVATE, "secretFunction", "private.invalid", "Authorization"):
            self.assertNotIn(forbidden, raw)
        self.assertLessEqual(len(raw.encode()), 65536)
        result = json.loads(raw)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["patch_attempts"], 0)
        return code, result

    def test_actual_entry_one_dry_query_filters_error_fields(self):
        peer = HTTPPeer()
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertEqual(result, {
            "status": "diagnostics_observed", "read_only": True, "patch_attempts": 0, "settings_reads": 1, "telemetry_queries": 1,
            "api": {"settings": {"http_status": 200, "api_error_codes": []}, "telemetry": {"http_status": 200, "api_error_codes": []}},
            "settings": {"owner_limit": {"present": True, "type": "plain_text", "value": 10},
                         "normalized_settings_sha256": hashlib.sha256(json.dumps(peer.settings, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
                         "observed_at": result["settings"]["observed_at"]},
            "telemetry": {"status": "observed", "returned_events": 1, "at_limit": False,
                          "omitted_projected_events": 0, "truncated_projection": False, "invocations": [{
                "scriptName": "crabbox-coordinator", "timestamp": FROM + 12000,
                "scriptVersion": {"id": VERSION}, "requestId": REQUEST_ID, "durableObjectId": DO_ID,
                "outcome": "exception", "statusCode": 500, "exception": {
                    "status": "recognized", "category": "TypeError", "locations": [
                        {"file": "src/fleet.ts", "line": 4335, "column": 12},
                        {"file": "index.js", "line": 900, "column": 3}],
                    "unrecognized_or_omitted_frames": True}}]},
        })
        self.assertEqual(len(peer.requests), 2)

    def test_old_transport_loses_http_reason_new_entry_preserves_numeric_only(self):
        class OldPeer:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                raise urllib.error.HTTPError(request.full_url, 403, PRIVATE, {}, io.BytesIO(
                    json.dumps({"success": False, "errors": [{"code": 10000, "message": TOKEN}]}).encode()))
        old_peer = OldPeer()
        with patch.object(OLD.urllib.request, "build_opener", return_value=old_peer):
            with self.assertRaisesRegex(OLD.Refusal, "^request_unavailable$"):
                OLD.Cloudflare(TOKEN).request("POST", OLD.TELEMETRY, OLD.QUERY)
        self.assertEqual(old_peer.calls, 1)
        for status in (302, 403, 500):
            peer = HTTPPeer(); peer.http_error = status
            peer.api_errors = [{"code": 10000, "message": TOKEN}, {"code": True}, {"code": PRIVATE}, {"code": -1}]
            code, result = self.invoke(peer)
            self.assertEqual((code, result["telemetry"]["reason"]), (1, "http_status"))
            self.assertEqual(result["api"]["telemetry"], {"http_status": status, "api_error_codes": [10000]})
            self.assertEqual(len(peer.requests), 2)

    def test_api_body_and_transport_failures_remain_bounded_without_retry(self):
        peer = HTTPPeer(); peer.api_errors = [{"code": 10001, "message": PRIVATE}]
        code, result = self.invoke(peer)
        self.assertEqual((code, result["telemetry"]["reason"], result["api"]["telemetry"]),
                         (1, "api_response", {"http_status": 200, "api_error_codes": [10001]}))
        for body, reason in [(b"private-not-json", "response_json"),
                             (b"x" * (2 * 1024 * 1024 + 1), "response_limit"),
                             (b'{"success":true,"success":true}', "response_json")]:
            peer = HTTPPeer(); peer.raw = body; peer.http_error = 403
            code, result = self.invoke(peer)
            self.assertEqual((code, result["telemetry"]["reason"], result["api"]["telemetry"]["http_status"]), (1, reason, 403))
            self.assertEqual(len(peer.requests), 2)
        peer = HTTPPeer()
        with patch.object(peer, "open", side_effect=OSError(TOKEN)):
            code, result = self.invoke(peer)
        self.assertEqual((code, result["telemetry"]["reason"]), (1, "request_unavailable"))

    def test_unknown_shapes_and_unapproved_frames_cannot_escape_projection(self):
        fixtures = [
            ([TOKEN], "unrecognized", [], False),
            ({"name": PRIVATE, "stack": "Error: " + TOKEN + "\n at /private/index.js:1:2"}, "Error", [], True),
            ({"error": {"name": "RangeError", "stack": "RangeError: " + TOKEN + "\n at node_modules/ssh2/lib/keygen.js:294:5"}},
             "RangeError", [{"file": "node_modules/ssh2/lib/keygen.js", "line": 294, "column": 5}], False),
            ("TypeError: " + TOKEN + "\n at index.js:2:3", "TypeError", [{"file": "index.js", "line": 2, "column": 3}], False),
            ({"message": "x" * 16385}, "unrecognized", [], True),
            ({"unknown": TOKEN}, "unrecognized", [], False),
        ]
        for source, category, locations, omitted in fixtures:
            peer = HTTPPeer(); peer.events[0]["source"] = source; peer.events[0]["$metadata"] = {}
            code, result = self.invoke(peer)
            self.assertEqual(code, 0)
            self.assertEqual(result["telemetry"]["invocations"][0]["exception"], {
                "status": "recognized" if category != "unrecognized" or locations else "unrecognized",
                "category": category, "locations": locations, "unrecognized_or_omitted_frames": omitted})

    def test_returned_scope_limits_and_timestamps(self):
        for mutate, reason in [
            (lambda p: p.events[0]["$workers"].update(scriptName="another-worker"), "telemetry_script_scope"),
            (lambda p: p.events[0].update(timestamp=TO + 1), "telemetry_time_scope"),
            (lambda p: p.events[0]["$workers"].update(requestId=TOKEN), "telemetry_identifier"),
            (lambda p: p.events.extend(copy.deepcopy(p.events[0]) for _ in range(200)), "telemetry_events_shape"),
        ]:
            peer = HTTPPeer(); mutate(peer)
            code, result = self.invoke(peer)
            self.assertEqual((code, result["telemetry"]["reason"]), (1, reason))
            self.assertEqual(result["telemetry"]["status"], "refused")
            self.assertEqual(len(peer.requests), 2)
        peer = HTTPPeer(); peer.events = []
        code, result = self.invoke(peer)
        self.assertEqual((code, result["telemetry"]["returned_events"]), (0, 0))
        peer = HTTPPeer(); peer.events *= 200
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertTrue(result["telemetry"]["at_limit"])
        peer = HTTPPeer(); later = copy.deepcopy(peer.events[0]); later["timestamp"] += 1; peer.events.append(later)
        code, result = self.invoke(peer)
        self.assertEqual([row["timestamp"] for row in result["telemetry"]["invocations"]], [FROM + 12000, FROM + 12001])

    def test_current_limit_projection_is_distinct_from_historical_events(self):
        for value in ("10", "20"):
            peer = HTTPPeer(); peer.settings["bindings"][0]["text"] = value
            code, result = self.invoke(peer)
            self.assertEqual(code, 0)
            self.assertEqual(result["settings"]["owner_limit"]["value"], int(value))
            datetime.fromisoformat(result["settings"]["observed_at"])
            self.assertEqual(len(peer.requests), 2)
        peer = HTTPPeer(); peer.settings["bindings"][0].update(type="secret_text", text=TOKEN)
        code, result = self.invoke(peer)
        self.assertEqual((code, result["settings"]["owner_limit"]), (0, {"present": True, "type": "secret_text"}))
        peer = HTTPPeer(); peer.settings["bindings"][0]["text"] = TOKEN
        code, result = self.invoke(peer)
        self.assertEqual((code, result["settings"]["reason"]), (1, "owner_limit_shape"))
        self.assertEqual(result["telemetry"]["status"], "observed")
        self.assertEqual(len(peer.requests), 2)
        peer = HTTPPeer(); peer.events = [dict(copy.deepcopy(peer.events[0]), timestamp=FROM+i) for i in range(200)]
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        projected = result["telemetry"]
        self.assertEqual(projected["returned_events"], 200)
        self.assertTrue(projected["at_limit"])
        self.assertTrue(projected["truncated_projection"])
        self.assertGreater(len(projected["invocations"]), 0)
        self.assertGreater(projected["omitted_projected_events"], 0)
        self.assertEqual(len(projected["invocations"]) + projected["omitted_projected_events"], 200)
        self.assertLessEqual(len(json.dumps(projected["invocations"]).encode()), 48 * 1024)
        self.assertEqual([row["timestamp"] for row in projected["invocations"]],
                         list(range(FROM, FROM + len(projected["invocations"]))))
        self.assertEqual(result["settings"]["owner_limit"]["value"], 10)
        self.assertEqual(result["api"]["telemetry"]["http_status"], 200)
        self.assertEqual(len(peer.requests), 2)

    def test_context_query_and_single_attempt_guards(self):
        for key, value in (("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_REPOSITORY", "another/repo")):
            peer = HTTPPeer(); env = dict(ENV, **{key: value})
            code, result = self.invoke(peer, env)
            self.assertEqual((code, result["reason"]), (1, "workflow_identity"))
            self.assertEqual(peer.requests, [])
        peer = HTTPPeer()
        with patch.object(MODULE.urllib.request, "build_opener", return_value=peer):
            api = MODULE.Cloudflare(TOKEN)
            changed = copy.deepcopy(EXPECTED_QUERY); changed["dry"] = False
            for args in (("PATCH", "/scripts/crabbox-coordinator/settings"), ("GET", "/scripts/another-worker/settings"),
                         ("POST", TELEMETRY, changed), ("POST", "/observability/queries", EXPECTED_QUERY)):
                with self.assertRaisesRegex(MODULE.Refusal, "^request_scope$"):
                    api.request(*args)
            self.assertEqual(peer.requests, [])
            api.request("GET", SETTINGS)
            api.request("POST", TELEMETRY, EXPECTED_QUERY)
            with self.assertRaisesRegex(MODULE.Refusal, "^request_already_attempted$"):
                api.request("POST", TELEMETRY, EXPECTED_QUERY)
            self.assertEqual(len(peer.requests), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
