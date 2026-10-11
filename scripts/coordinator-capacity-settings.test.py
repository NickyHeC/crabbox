"""Run the actual GET-only workflow entry with secretless in-memory HTTP."""

import contextlib
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
MODULE = types.ModuleType("capacity_shape_workflow")
exec(compile(SOURCE, str(WORKFLOW), "exec"), MODULE.__dict__)
TOKEN = "synthetic-private-token"
PRIVATE = "synthetic-private-response"
VERSION = "11111111-1111-4111-8111-111111111111"
OWNERS = "CRABBOX_CAPACITY_ADMIN_OWNERS"
LIMIT = "CRABBOX_MAX_ACTIVE_LEASES_PER_CAPACITY_ADMIN"
BASE = "https://api.cloudflare.com/client/v4/accounts/91b59577e757131d68d55a471fe32aca/workers/scripts/crabbox-coordinator"
ENV = {
    "GITHUB_REPOSITORY": "openclaw/crabbox",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/ops/capacity-settings-20261011",
    "GITHUB_WORKFLOW_REF": "openclaw/crabbox/.github/workflows/coordinator-deploy.yml@refs/heads/ops/capacity-settings-20261011",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_WORKFLOW_SHA": "a" * 40,
    "GITHUB_RUN_ATTEMPT": "1",
    "CLOUDFLARE_API_TOKEN": TOKEN,
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
    def __init__(self, bindings):
        self.bindings = bindings
        self.requests = []
        self.error = False

    def open(self, request, timeout):
        assert request.get_method() == "GET" and request.data is None
        assert timeout == 30 and request.get_header("Authorization") == "Bearer " + TOKEN
        assert request.full_url.startswith(BASE + "/")
        path = request.full_url[len(BASE):]
        self.requests.append(path)
        if self.error:
            raise urllib.error.HTTPError(request.full_url, 403, PRIVATE, {}, io.BytesIO(TOKEN.encode()))
        responses = {
            "/settings": {"bindings": self.bindings, "annotations": {"workers/message": PRIVATE}},
            "/versions?per_page=1": {"items": [{"id": VERSION}]},
            "/deployments": {"deployments": [{"versions": [{"version_id": VERSION, "percentage": 100}]}]},
            "/versions/" + VERSION: {"id": VERSION, "resources": {
                "script": {"etag": PRIVATE}, "script_runtime": {"compatibility_date": "2026-07-01"}}},
        }
        assert path in responses
        return Response(json.dumps({"success": True, "errors": [], "result": responses[path]}).encode())


class ShapeTests(unittest.TestCase):
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
        self.assertLess(len(raw), 2048)
        result = json.loads(raw)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["patch_attempts"], 0)
        return code, result

    def test_actual_entry_reports_only_target_shapes_and_four_gets(self):
        peer = HTTPPeer([
            {"name": OWNERS, "type": "plain_text", "text": PRIVATE, PRIVATE: PRIVATE, "version_id": PRIVATE},
            {"name": LIMIT, "type": "secret_text"},
            {"name": PRIVATE, "type": "plain_text", "text": TOKEN},
        ])
        code, result = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "binding_shapes_observed")
        self.assertEqual(result["bindings"], {
            OWNERS: {"present": True, "type": "plain_text", "fields": ["name", "text", "type", "version_id"],
                     "unknown_field_count": 1, "text_present": True, "text_type": "string", "text_empty": False},
            LIMIT: {"present": True, "type": "secret_text", "fields": ["name", "type"],
                    "unknown_field_count": 0, "text_present": False, "text_type": "absent", "text_empty": False},
        })
        self.assertEqual(peer.requests, ["/settings", "/versions?per_page=1", "/deployments", "/versions/" + VERSION])

    def test_absent_unknown_and_nonstring_text_never_publish_values(self):
        values = [(None, "null"), (True, "boolean"), (314159, "number"), ([PRIVATE], "array"),
                  ({PRIVATE: TOKEN}, "object"), ("", "string")]
        for value, kind in values:
            peer = HTTPPeer([{"name": LIMIT, "type": PRIVATE, "text": value}])
            code, result = self.invoke(peer)
            self.assertEqual(code, 0)
            self.assertEqual(result["bindings"][OWNERS], {"present": False})
            self.assertEqual(result["bindings"][LIMIT], {
                "present": True, "type": "other", "fields": ["name", "text", "type"],
                "unknown_field_count": 0, "text_present": True, "text_type": kind, "text_empty": value == "",
            })

    def test_duplicate_binding_and_http_failure_remain_private_refusals(self):
        row = {"name": LIMIT, "type": "plain_text", "text": PRIVATE}
        for peer, reason in ((HTTPPeer([row, row]), "duplicate_binding"), (HTTPPeer([]), "request_unavailable")):
            peer.error = reason == "request_unavailable"
            code, result = self.invoke(peer)
            self.assertEqual((code, result["status"], result["reason"]), (1, "refused", reason))
            self.assertEqual(peer.requests, ["/settings"])

    def test_wrong_context_and_write_method_cannot_reach_transport(self):
        peer = HTTPPeer([])
        code, result = self.invoke(peer, {**ENV, "GITHUB_RUN_ATTEMPT": "2"})
        self.assertEqual((code, result["reason"], peer.requests), (1, "workflow_identity", []))
        with patch.object(MODULE.urllib.request, "build_opener", return_value=peer):
            client = MODULE.Cloudflare(TOKEN)
            with self.assertRaisesRegex(MODULE.Refusal, "^request_scope$"):
                client.request("PATCH", "/settings")
        self.assertEqual(peer.requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
