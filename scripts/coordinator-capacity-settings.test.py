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
TARGET = "CRABBOX_MAX_ACTIVE_LEASES_PER_OWNER"
GLOBAL = "CRABBOX_MAX_ACTIVE_LEASES"
ORG = "CRABBOX_MAX_ACTIVE_LEASES_PER_ORG"
ADMIN = "CRABBOX_MAX_ACTIVE_LEASES_PER_CAPACITY_ADMIN"
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
            {"name": TARGET, "type": "plain_text", "text": "10"},
            {"name": ORG, "type": "plain_text", "text": "50"},
            {"name": "UNRELATED_PRIVATE_VALUE", "type": "plain_text", "text": "never-output-body"},
            {"name": OWNERS, "type": "secret_text"},
            {"name": ADMIN, "type": "plain_text", "text": "50"},
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


def row(peer, name):
    return next(value for value in peer.before["bindings"] if value["name"] == name)


def target_hash():
    value = settings()
    for binding in value["bindings"]:
        if binding["name"] == TARGET:
            binding["text"] = "20"
    value["bindings"] = {binding["name"]: binding for binding in value["bindings"]}
    del value["annotations"]["workers/triggered_by"]
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class OwnerCapacityTests(unittest.TestCase):
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
        for private in (TOKEN, "never-output-body", "private transport"):
            self.assertNotIn(private, raw)
        return code, json.loads(raw)

    def test_actual_entry_changes_only_owner_limit_and_records_conditional_restoration(self):
        peer = HTTPPeer()
        code, result = self.invoke(peer)
        self.assertEqual((code, result["status"], result["patch_attempts"]), (0, "applied_readback_verified", 1))
        self.assertEqual(peer.requests, [("GET", path) for path in
                         ("/settings", "/versions?per_page=1", "/deployments", "/versions/" + OLD)] * 2
                         + [("PATCH", "/settings")] + [("GET", path) for path in
                         ("/settings", "/versions?per_page=1", "/deployments", "/versions/" + NEW)])
        payload = peer.patches[0]
        self.assertEqual(set(payload), {"bindings", "annotations"})
        self.assertEqual(payload["annotations"], {"workers/message": "keep message", "workers/tag": "keep tag"})
        bindings = {binding["name"]: binding for binding in payload["bindings"]}
        self.assertEqual(bindings[TARGET], {"name": TARGET, "type": "plain_text", "text": "20"})
        for name in {binding["name"] for binding in peer.before["bindings"]} - {TARGET}:
            self.assertEqual(bindings[name], {"name": name, "type": "inherit"})
        self.assertEqual(result["expected_settings_sha256"], target_hash())
        self.assertEqual((result["original_owner_limit"], result["owner_limit"], result["conditional_restore_target"]), (10, 20, 10))
        self.assertTrue(result["restore_requires_review"])
        self.assertTrue(result["code_unchanged"])

    def test_missing_opaque_invalid_target_and_surrounding_caps_refuse_before_patch(self):
        changes = [lambda p: row(p, TARGET).update(type="secret_text"),
                   lambda p: row(p, TARGET).update(text=10),
                   lambda p: row(p, TARGET).update(extra="private"),
                   lambda p: p.before["bindings"].remove(row(p, TARGET))]
        changes += [lambda p, value=value: row(p, TARGET).update(text=value)
                    for value in ("0", "15", "010", "30", "NaN")]
        for name in (GLOBAL, ORG, ADMIN):
            changes += [lambda p, name=name: row(p, name).update(text="19"),
                        lambda p, name=name: row(p, name).update(text="0"),
                        lambda p, name=name: row(p, name).update(text="Infinity"),
                        lambda p, name=name: row(p, name).update(type="secret_text"),
                        lambda p, name=name: p.before["bindings"].remove(row(p, name))]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                peer = HTTPPeer(); change(peer)
                code, result = self.invoke(peer)
                self.assertEqual((code, result["status"], result["patch_attempts"], peer.patches), (1, "refused", 0, []))
                self.assertIn(result["reason"], {"capacity_binding_type", "capacity_limit_invalid", "owner_limit_changed", "surrounding_limit_too_low"})

    def test_existing_twenty_is_noop_with_opaque_membership_preserved(self):
        peer = HTTPPeer(); row(peer, TARGET)["text"] = "20"
        code, result = self.invoke(peer)
        self.assertEqual((code, result["status"], result["owner_limit"], result["patch_attempts"], peer.patches),
                         (0, "already_present", 20, 0, []))
        self.assertNotIn("conditional_restore_target", result)

    def test_prewrite_drift_and_postwrite_unrelated_drift_are_not_accepted(self):
        peer = HTTPPeer(); peer.prewrite = lambda p: row(p, GLOBAL).update(text="60")
        code, result = self.invoke(peer)
        self.assertEqual((code, result["reason"], peer.patches), (1, "prewrite_changed", []))
        for change in (lambda p: p.after["bindings"].pop(0),
                       lambda p: p.after["annotations"].update({"workers/message": "changed"}),
                       lambda p: p.after["limits"].update(cpu_ms=20000)):
            peer = HTTPPeer(); peer.postwrite = change
            code, result = self.invoke(peer)
            self.assertEqual((code, result["status"], result["reason"], len(peer.patches)),
                             (1, "requires_reconciliation", "postwrite_settings_mismatch", 1))
            self.assertEqual(result["expected_settings_sha256"], target_hash())
        for mode in ("code_changed", "runtime_changed"):
            peer = HTTPPeer(); peer.response_mode = mode
            code, result = self.invoke(peer)
            self.assertEqual((code, result["reason"], len(peer.patches)), (1, "postwrite_code_mismatch", 1))

    def test_ambiguous_patch_reconciles_only_by_get_against_fixed_target_hash(self):
        for mode, expected in (("lost_before_apply", 1), ("lost_after_apply", 0)):
            peer = HTTPPeer(); peer.response_mode = mode
            code, result = self.invoke(peer)
            self.assertEqual(code, expected)
            self.assertFalse(result["patch_response_confirmed"])
            self.assertEqual(result["expected_settings_sha256"], target_hash())
            self.assertEqual(len(peer.patches), 1)
            at = peer.requests.index(("PATCH", "/settings"))
            self.assertTrue(all(method == "GET" for method, _ in peer.requests[at + 1:]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
