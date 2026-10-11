"""Exercise the actual inline workflow entry point with an in-memory HTTP peer."""

import contextlib
import copy
import email.parser
import email.policy
import hashlib
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
MODULE = types.ModuleType("capacity_workflow")
exec(compile(SOURCE, str(WORKFLOW), "exec"), MODULE.__dict__)
OLD = "11111111-1111-4111-8111-111111111111"
NEW = "22222222-2222-4222-8222-222222222222"
TOKEN = "synthetic-never-output-token"
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


def settings():
    return {
        "bindings": [
            {"name": "CRABBOX_ADMIN_TOKEN", "type": "secret_text"},
            {"name": "FLEET", "type": "durable_object_namespace", "namespace_id": "opaque"},
            {"name": "ARTIFACTS", "type": "r2_bucket", "bucket_name": "preserved"},
            {"name": "CRABBOX_MAX_ACTIVE_LEASES", "type": "plain_text", "text": "50"},
            {"name": "CRABBOX_MAX_ACTIVE_LEASES_PER_OWNER", "type": "plain_text", "text": "10"},
            {"name": "UNRELATED_PRIVATE_VALUE", "type": "plain_text", "text": "never-output-body"},
            {"name": OWNERS, "type": "plain_text", "text": "service:existing,github:123"},
            {"name": LIMIT, "type": "plain_text", "text": "10"},
        ],
        "annotations": {"workers/message": "keep message", "workers/tag": "keep tag", "workers/triggered_by": "wrangler"},
        "compatibility_date": "2026-07-01",
        "compatibility_flags": ["nodejs_compat"],
        "observability": {"enabled": True, "head_sampling_rate": 0.5},
        "limits": {"cpu_ms": 10000},
        "placement": {"mode": "smart"},
    }


def version(identity):
    return {"id": identity, "resources": {
        "script": {"etag": "same-code-hash", "handlers": ["fetch"], "last_deployed_from": "api"},
        "script_runtime": {"compatibility_date": "2026-07-01", "compatibility_flags": ["nodejs_compat"]},
    }}


class Response(io.BytesIO):
    status = 200


class HTTPPeer:
    def __init__(self):
        self.before = settings()
        self.after = None
        self.requests = []
        self.patches = []
        self.read_round = 0
        self.prewrite = None
        self.postwrite = None
        self.response_mode = None
        self.split = False
        self.undeployed = False

    def open(self, request, timeout):
        assert timeout == 30
        assert request.get_header("Authorization") == "Bearer " + TOKEN
        assert request.full_url.startswith(BASE + "/")
        path = request.full_url[len(BASE):]
        method = request.get_method()
        self.requests.append((method, path))
        if method == "PATCH":
            assert path == "/settings" and not self.patches
            message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
                ("Content-Type: " + request.get_header("Content-type") + "\r\n\r\n").encode() + request.data
            )
            parts = list(message.iter_parts())
            assert len(parts) == 1 and parts[0].get_param("name", header="content-disposition") == "settings"
            assert parts[0].get_content_type() == "application/json"
            payload = json.loads(parts[0].get_payload(decode=True))
            self.patches.append(payload)
            if self.response_mode == "lost_before_apply":
                raise TimeoutError("private transport detail " + TOKEN)
            original = {row["name"]: row for row in self.before["bindings"]}
            self.after = copy.deepcopy(self.before)
            self.after["bindings"] = [copy.deepcopy(original[row["name"]]) if row["type"] == "inherit"
                                      else copy.deepcopy(row) for row in payload["bindings"]]
            self.after["annotations"] = {**payload["annotations"], "workers/triggered_by": "api"}
            if self.postwrite:
                self.postwrite(self)
            if self.response_mode == "lost_after_apply":
                raise TimeoutError("private transport detail " + TOKEN)
            result = self.after
        else:
            assert method == "GET"
            if path == "/settings":
                self.read_round += 1
                if self.read_round == 2 and self.prewrite:
                    self.prewrite(self)
                if self.response_mode == "http_error":
                    raise urllib.error.HTTPError(request.full_url, 403, TOKEN, {}, io.BytesIO(TOKEN.encode()))
                if self.response_mode == "malformed":
                    return Response(TOKEN.encode())
                if self.response_mode == "oversized":
                    return Response(b"x" * (MODULE.MAX_RESPONSE + 1))
                result = self.after if self.after is not None else self.before
            elif path == "/versions?per_page=1":
                result = {"items": [{"id": NEW if self.after is not None or self.undeployed else OLD}]}
            elif path == "/deployments":
                active = NEW if self.after is not None else OLD
                rows = [{"version_id": active, "percentage": 100}]
                if self.split:
                    rows = [{"version_id": OLD, "percentage": 50}, {"version_id": NEW, "percentage": 50}]
                result = {"deployments": [{"id": "deployment-" + active, "strategy": "percentage", "versions": rows}]}
            elif path in ("/versions/" + OLD, "/versions/" + NEW):
                result = version(path.rsplit("/", 1)[1])
                if self.response_mode == "code_changed" and self.after is not None:
                    result["resources"]["script"]["etag"] = "other-code"
                if self.response_mode == "runtime_changed" and self.after is not None:
                    result["resources"]["script_runtime"]["compatibility_flags"] = []
            else:
                raise AssertionError("unexpected endpoint")
        return Response(json.dumps({"success": True, "errors": [], "result": result}).encode())


class CapacityTests(unittest.TestCase):
    def invoke(self, peer, env=None):
        output = io.StringIO()
        def opener(*handlers):
            self.assertEqual(len(handlers), 1)
            self.assertIsInstance(handlers[0], MODULE.NoRedirect)
            self.assertIsNone(handlers[0].redirect_request(None, None, 302, "private", {}, "https://elsewhere.invalid"))
            return peer
        with patch.dict(os.environ, ENV if env is None else env, clear=True), \
             patch.object(MODULE.urllib.request, "build_opener", side_effect=opener), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = MODULE.main()
        raw = output.getvalue()
        self.assertNotIn(TOKEN, raw)
        self.assertNotIn("never-output-body", raw)
        self.assertNotIn("private transport", raw)
        return code, json.loads(raw)

    def test_actual_inline_entry_changes_only_two_bindings_and_preserves_annotations(self):
        peer = HTTPPeer()
        code, report = self.invoke(peer)
        self.assertEqual((code, report["status"], report["patch_attempts"]), (0, "applied_readback_verified", 1))
        self.assertEqual(peer.requests, [("GET", path) for path in
                         ("/settings", "/versions?per_page=1", "/deployments", "/versions/" + OLD)] * 2
                         + [("PATCH", "/settings")] + [("GET", path) for path in
                         ("/settings", "/versions?per_page=1", "/deployments", "/versions/" + NEW)])
        body = peer.patches[0]
        self.assertEqual(set(body), {"bindings", "annotations"})
        self.assertEqual(body["annotations"], {"workers/message": "keep message", "workers/tag": "keep tag"})
        rows = {row["name"]: row for row in body["bindings"]}
        for name in {row["name"] for row in peer.before["bindings"]} - {OWNERS, LIMIT}:
            self.assertEqual(rows[name], {"name": name, "type": "inherit"})
        self.assertEqual(rows[OWNERS]["text"], "service:existing,github:123,github:25068")
        self.assertEqual(rows[LIMIT]["text"], "20")
        self.assertTrue(report["code_unchanged"])

    def test_absent_owner_binding_and_higher_cap_and_noop(self):
        peer = HTTPPeer()
        peer.before["bindings"].pop(-2)
        del peer.before["annotations"]
        code, report = self.invoke(peer)
        self.assertEqual(code, 0)
        self.assertEqual(peer.patches[0]["bindings"][-2:], [
            {"name": OWNERS, "type": "plain_text", "text": "github:25068"},
            {"name": LIMIT, "type": "plain_text", "text": "20"},
        ])
        peer = HTTPPeer()
        peer.before["bindings"][-1]["text"] = "0040"
        code, report = self.invoke(peer)
        self.assertEqual((code, report["capacity_admin_limit"]), (0, 40))
        self.assertEqual(peer.patches[0]["bindings"][-1]["text"], "0040")
        peer = HTTPPeer()
        peer.before["bindings"][-2]["text"] = " GITHUB:25068 ,service:existing"
        peer.before["bindings"][-1]["text"] = "40"
        code, report = self.invoke(peer)
        self.assertEqual((code, report["status"], peer.patches), (0, "already_present", []))

    def test_invalid_target_types_limits_duplicates_and_versions_fail_before_patch(self):
        cases = [
            (lambda p: p.before["bindings"].pop(-1), "capacity_limit_missing"),
            (lambda p: p.before["bindings"][-2].update(type="secret_text"), "capacity_binding_type"),
            (lambda p: p.before["bindings"].append(copy.deepcopy(p.before["bindings"][0])), "duplicate_binding"),
            (lambda p: setattr(p, "split", True), "latest_not_fully_deployed"),
            (lambda p: setattr(p, "undeployed", True), "latest_not_fully_deployed"),
        ]
        cases += [(lambda p, value=value: p.before["bindings"][-1].update(text=value), "capacity_limit_invalid")
                  for value in ("0", "-1", "Infinity", "NaN", "20junk", "2.5", "9007199254740992")]
        for change, reason in cases:
            with self.subTest(reason=reason):
                peer = HTTPPeer(); change(peer)
                code, report = self.invoke(peer)
                self.assertEqual((code, report["reason"], peer.patches), (1, reason, []))

    def test_immediate_reread_detects_concurrent_settings_change(self):
        peer = HTTPPeer()
        peer.prewrite = lambda p: p.before["limits"].update(cpu_ms=20000)
        code, report = self.invoke(peer)
        self.assertEqual((code, report["reason"], peer.patches), (1, "prewrite_changed", []))

    def test_readback_rejects_unrelated_binding_settings_annotation_code_and_runtime_changes(self):
        changes = [
            lambda p: p.after["bindings"].pop(0),
            lambda p: p.after["bindings"][0].update(type="plain_text", text="unexpected"),
            lambda p: p.after["limits"].update(cpu_ms=20000),
            lambda p: p.after["annotations"].update({"workers/message": "changed"}),
        ]
        for change in changes:
            peer = HTTPPeer(); peer.postwrite = change
            code, report = self.invoke(peer)
            self.assertEqual((code, report["status"], report["reason"]),
                             (1, "requires_reconciliation", "postwrite_settings_mismatch"))
            self.assertEqual(len(peer.patches), 1)
        for mode in ("code_changed", "runtime_changed"):
            peer = HTTPPeer(); peer.response_mode = mode
            code, report = self.invoke(peer)
            self.assertEqual((code, report["reason"], len(peer.patches)), (1, "postwrite_code_mismatch", 1))

    def test_ambiguous_patch_reconciles_by_get_only_without_replay(self):
        for mode, expected in (("lost_before_apply", 1), ("lost_after_apply", 0)):
            peer = HTTPPeer(); peer.response_mode = mode
            target = settings()
            target["bindings"][-2]["text"] = "service:existing,github:123,github:25068"
            target["bindings"][-1]["text"] = "20"
            target["bindings"] = {row["name"]: row for row in target["bindings"]}
            del target["annotations"]["workers/triggered_by"]
            target_hash = hashlib.sha256(json.dumps(target, sort_keys=True,
                separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            code, report = self.invoke(peer)
            self.assertEqual(code, expected)
            self.assertEqual(report["expected_settings_sha256"], target_hash)
            self.assertFalse(report["patch_response_confirmed"])
            self.assertEqual(len(peer.patches), 1)
            at = peer.requests.index(("PATCH", "/settings"))
            self.assertTrue(all(method == "GET" for method, _ in peer.requests[at + 1:]))

    def test_http_failures_and_bounds_never_expose_remote_error_or_token(self):
        for mode, reason in (("http_error", "request_unavailable"), ("malformed", "request_unavailable"),
                             ("oversized", "response_limit")):
            peer = HTTPPeer(); peer.response_mode = mode
            code, report = self.invoke(peer)
            self.assertEqual((code, report["reason"], peer.patches), (1, reason, []))

    def test_wrong_execution_context_missing_token_and_rerun_cannot_reach_http(self):
        for key, value in (("GITHUB_REPOSITORY", "other/repo"), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_REF", "refs/heads/main"), ("GITHUB_WORKFLOW_SHA", "b" * 40),
                           ("GITHUB_RUN_ATTEMPT", "2"), ("CLOUDFLARE_API_TOKEN", "")):
            peer = HTTPPeer()
            code, report = self.invoke(peer, {**ENV, key: value})
            self.assertEqual(code, 1)
            self.assertEqual(peer.requests, [])

    def test_workflow_has_no_code_checkout_deploy_or_other_secret_surface(self):
        header = TEXT.split("        run: |\n", 1)[0]
        self.assertIn("on:\n  workflow_dispatch:\n", header)
        self.assertIn("group: coordinator-deploy\n  cancel-in-progress: false", header)
        self.assertIn("environment: coordinator", header)
        self.assertIn("permissions:\n  contents: read", header)
        self.assertEqual(header.count("      - name:"), 1)
        self.assertNotIn("uses:", header)
        self.assertNotIn("  push:", header)
        self.assertEqual(header.count("secrets."), 1)
        self.assertTrue(SHELL.startswith("python3 -I -B - <<'PY'\n"))
        self.assertTrue(SHELL.endswith("\nPY\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
