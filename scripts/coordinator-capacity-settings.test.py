"""Exercise the actual read-only diagnostic entry with a secretless HTTP peer."""

import contextlib
import copy
from datetime import datetime
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import urllib.error

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/coordinator-deploy.yml"
TEXT = WORKFLOW.read_text()
SHELL = "\n".join(line[10:] for line in TEXT.split("        run: |\n", 1)[1].splitlines()) + "\n"
SOURCE = SHELL.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0]
MODULE = types.ModuleType("capacity_serving_diagnostic")
exec(compile(SOURCE, str(WORKFLOW), "exec"), MODULE.__dict__)
TOKEN = "synthetic-private-token"
PRIVATE = "synthetic-private-response"
VERSION = "11111111-1111-4111-8111-111111111111"
NAMESPACE = "a" * 32
DO_ID = "b" * 64
REQUEST_ID = "c" * 16
BASE = "https://api.cloudflare.com/client/v4/accounts/91b59577e757131d68d55a471fe32aca/workers"
SETTINGS = "/scripts/crabbox-coordinator/settings"
NAMESPACES = "/durable_objects/namespaces?per_page=1000&page=1"
TELEMETRY = "/observability/telemetry/query"
TARGET = "CRABBOX_MAX_ACTIVE_LEASES_PER_OWNER"
FROM = int(datetime.fromisoformat("2026-10-11T23:51:30+00:00").timestamp() * 1000)
TO = int(datetime.fromisoformat("2026-10-11T23:52:30+00:00").timestamp() * 1000)
EXPECTED_QUERY = {
    "queryId": "capacity-serving-version-20261011", "dry": True,
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
        self.fail = None
        self.settings = {"bindings": [
            {"name": TARGET, "type": "plain_text", "text": "20", PRIVATE: TOKEN},
            {"name": "FLEET", "type": "durable_object_namespace", "namespace_id": NAMESPACE,
             "class_name": "FleetDurableObject", PRIVATE: TOKEN},
            {"name": "CRABBOX_CAPACITY_ADMIN_OWNERS", "type": "secret_text", "text": TOKEN},
            {"name": PRIVATE, "type": "plain_text", "text": TOKEN},
        ], "annotations": {"workers/message": PRIVATE}}
        self.namespaces = [
            {"id": NAMESPACE, "class": "FleetDurableObject", "script": "crabbox-coordinator",
             "name": PRIVATE, PRIVATE: TOKEN},
            {"id": "d" * 32, "class": PRIVATE, "script": PRIVATE},
        ]
        self.events = [{"timestamp": FROM + 28637, "source": {"message": PRIVATE, "token": TOKEN},
                        "$metadata": {"message": PRIVATE, "url": TOKEN}, "$workers": {
                            "scriptName": "crabbox-coordinator", "scriptVersion": {"id": VERSION, "tag": TOKEN},
                            "requestId": REQUEST_ID, "durableObjectId": DO_ID, "outcome": "ok",
                            "event": {"request": {"headers": {"Authorization": TOKEN}}},
                        }}]

    def open(self, request, timeout):
        assert timeout == 30
        assert request.get_header("Authorization") == "Bearer " + TOKEN
        route = (request.get_method(), request.full_url)
        self.requests.append(route)
        allowed = [("GET", BASE + SETTINGS), ("GET", BASE + NAMESPACES), ("POST", BASE + TELEMETRY)]
        assert route == allowed[len(self.requests) - 1]
        if len(self.requests) < 3:
            assert request.data is None
        else:
            assert request.get_header("Content-type") == "application/json"
            assert json.loads(request.data) == EXPECTED_QUERY
        if self.fail == len(self.requests):
            raise urllib.error.HTTPError(request.full_url, 403, PRIVATE, {}, io.BytesIO(TOKEN.encode()))
        result = [self.settings, self.namespaces, {"events": {"events": self.events}}][len(self.requests) - 1]
        return Response(json.dumps({"success": True, "errors": [], "result": result}).encode())


class ServingTests(unittest.TestCase):
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
        self.assertNotIn(TOKEN, raw)
        self.assertNotIn(PRIVATE, raw)
        self.assertLessEqual(len(raw.encode()), 65536)
        result = json.loads(raw)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["patch_attempts"], 0)
        return code, result

    def test_registered_entry_returns_only_reviewed_metadata_from_three_reads(self):
        peer = HTTPPeer()
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertEqual(result, {
            "status": "serving_route_observed", "read_only": True, "patch_attempts": 0, "telemetry_queries": 1,
            "owner_limit": {"type": "plain_text", "text": "20"},
            "fleet_binding": {"name": "FLEET", "type": "durable_object_namespace",
                              "namespace_id": NAMESPACE, "class_name": "FleetDurableObject"},
            "fleet_namespace": {"id": NAMESPACE, "class": "FleetDurableObject", "script": "crabbox-coordinator"},
            "telemetry": {"status": "observed", "returned_events": 1, "at_limit": False, "invocations": [{
                "scriptName": "crabbox-coordinator", "timestamp": FROM + 28637, "scriptVersion": {"id": VERSION},
                "requestId": REQUEST_ID, "durableObjectId": DO_ID, "outcome": "ok"}]},
        })
        self.assertEqual(len(peer.requests), 3)

    def test_route_refusals_cannot_query_unrelated_telemetry(self):
        mutations = [
            (lambda p: p.settings["bindings"][0].update(text=TOKEN), "owner_limit_shape", 1),
            (lambda p: p.settings["bindings"][1].update(namespace_id=PRIVATE), "fleet_id", 1),
            (lambda p: p.namespaces.clear(), "fleet_namespace_not_unique_on_first_page", 2),
            (lambda p: p.namespaces.append(copy.deepcopy(p.namespaces[0])), "fleet_namespace_not_unique_on_first_page", 2),
            (lambda p: p.namespaces[0].update(script="another-worker"), "fleet_route_mismatch", 2),
            (lambda p: p.settings["bindings"][1].update(script_name="another-worker"), "fleet_route_mismatch", 2),
            (lambda p: p.settings["bindings"][1].update(environment="preview"), "fleet_route_mismatch", 2),
            (lambda p: p.settings["bindings"][1].update(dispatch_namespace="another-namespace"), "fleet_route_mismatch", 2),
        ]
        for mutate, reason, calls in mutations:
            with self.subTest(reason=reason):
                peer = HTTPPeer(); mutate(peer)
                code, result = self.invoke(peer)
                self.assertEqual((code, result["reason"], result["telemetry_queries"]), (1, reason, 0))
                self.assertEqual(len(peer.requests), calls)

    def test_telemetry_refusal_preserves_prior_facts_without_retry_or_raw_errors(self):
        for failing_call in (1, 2, 3):
            peer = HTTPPeer(); peer.fail = failing_call
            code, result = self.invoke(peer)
            self.assertEqual((code, result["reason"]), (1, "request_unavailable"))
            self.assertEqual(len(peer.requests), failing_call)
            if failing_call == 3:
                self.assertEqual(result["owner_limit"]["text"], "20")
                self.assertEqual(result["fleet_namespace"]["id"], NAMESPACE)
                self.assertEqual(result["telemetry_queries"], 1)
        peer = HTTPPeer(); peer.events = []
        code, result = self.invoke(peer)
        self.assertEqual((code, result["telemetry"]["returned_events"]), (0, 0))
        self.assertEqual(result["telemetry"]["invocations"], [])

    def test_returned_event_scope_caps_and_identifier_privacy(self):
        mutations = [
            (lambda p: p.events[0]["$workers"].update(scriptName="another-worker"), "telemetry_script_scope"),
            (lambda p: p.events[0].update(timestamp=TO + 1), "telemetry_time_scope"),
            (lambda p: p.events[0]["$workers"].update(requestId=TOKEN), "telemetry_identifier"),
            (lambda p: p.events.extend(copy.deepcopy(p.events[0]) for _ in range(200)), "telemetry_events_shape"),
        ]
        for mutate, reason in mutations:
            with self.subTest(reason=reason):
                peer = HTTPPeer(); mutate(peer)
                code, result = self.invoke(peer)
                self.assertEqual((code, result["reason"]), (1, reason))
                self.assertNotIn("telemetry", result)
                self.assertEqual(len(peer.requests), 3)
        peer = HTTPPeer()
        peer.events[0]["$workers"]["outcome"] = TOKEN
        peer.events.extend(copy.deepcopy(peer.events[0]) for _ in range(199))
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertTrue(result["telemetry"]["at_limit"])
        self.assertEqual(result["telemetry"]["invocations"][0]["outcome"], "other")
        peer = HTTPPeer()
        later = copy.deepcopy(peer.events[0]); later["timestamp"] += 1
        peer.events.append(later)
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertEqual([row["timestamp"] for row in result["telemetry"]["invocations"]],
                         [FROM + 28637, FROM + 28638])

    def test_context_and_transport_reject_writes_and_changed_queries_before_send(self):
        for key, value in (("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_WORKFLOW_SHA", "b" * 40)):
            peer = HTTPPeer(); env = dict(ENV, **{key: value})
            code, result = self.invoke(peer, env)
            self.assertEqual((code, result["reason"]), (1, "workflow_identity"))
            self.assertEqual(peer.requests, [])
        peer = HTTPPeer()
        with patch.object(MODULE.urllib.request, "build_opener", return_value=peer):
            api = MODULE.Cloudflare(TOKEN)
            changed = copy.deepcopy(EXPECTED_QUERY); changed["dry"] = False
            for args in (("PATCH", SETTINGS), ("POST", TELEMETRY, changed),
                         ("GET", "/scripts/another-worker/settings"), ("POST", "/observability/queries", EXPECTED_QUERY)):
                with self.assertRaisesRegex(MODULE.Refusal, "^request_scope$"):
                    api.request(*args)
            self.assertEqual(peer.requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
