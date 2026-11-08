"""Synthetic policy tests. No GitHub/Drive credentials or remote writes used."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from governance_gateway.policy import (
    ACTION_DOCS,
    ACTION_GIT,
    ControlSnapshot,
    Intent,
    LeaseSnapshot,
    TrustedSnapshot,
    VerifiedApproval,
    evaluate,
)

MAIN = "a" * 40
CONTROL = "b" * 40
NOW = datetime(2026, 11, 8, 10, 0, tzinfo=timezone.utc)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.intent = Intent(
            project_id="MOCHIFX",
            action=ACTION_GIT,
            request_id="REQ-001",
            nonce="nonce-once",
            owner_generation=7,
            lease_epoch=20,
            session_id="session-current",
            work_item="P0-ONLY",
            target="governance_gateway/policy.py",
            branch="p0/scoped",
            expected_main_sha=MAIN,
            expected_control_sha=CONTROL,
        )
        self.lease = LeaseSnapshot(
            project_id="MOCHIFX",
            state="HELD",
            owner_generation=7,
            epoch=20,
            session_id="session-current",
            work_item="P0-ONLY",
            expires_at=NOW + timedelta(minutes=5),
        )
        self.control = ControlSnapshot(
            project_id="MOCHIFX",
            ref_sha=CONTROL,
            state="ACTIVE",
            writer_state="HELD",
            permit_write=True,
            protected=True,
            owner_generation=7,
        )
        self.approval = VerifiedApproval(
            issuer_authenticated=True,
            conversation_bound=True,
            owner_approved_out_of_band=True,
            git_writer_credential_isolated=True,
            drive_writer_credential_isolated=True,
            nonce_atomically_reserved=True,
            request_id="REQ-001",
            nonce="nonce-once",
            session_id="session-current",
            work_item="P0-ONLY",
            target="governance_gateway/policy.py",
        )
        self.snapshot = TrustedSnapshot(
            owner_generation=7,
            lease=self.lease,
            control=self.control,
            main_sha=MAIN,
            allowed_targets=frozenset({"governance_gateway/policy.py", "DOC-ALLOWED"}),
            allowed_git_branches=frozenset({"p0/scoped"}),
            docs_revisions={"DOC-ALLOWED": "revision-expected"},
            approval=self.approval,
        )

    def verdict(self, *, intent=None, snapshot=None, now=None):
        return evaluate(
            self.intent if intent is None else intent,
            self.snapshot if snapshot is None else snapshot,
            NOW if now is None else now,
        )

    def deny(self, expected, *, intent=None, snapshot=None, now=None):
        result = self.verdict(intent=intent, snapshot=snapshot, now=now)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, expected)

    def test_hypothetical_trusted_git_preflight_only(self):
        result = self.verdict()
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "POLICY_PREFLIGHT_ONLY")

    def test_hypothetical_trusted_docs_preflight_only(self):
        intent = replace(
            self.intent, action=ACTION_DOCS, target="DOC-ALLOWED",
            branch=None, expected_doc_revision="revision-expected",
        )
        context = replace(self.snapshot, approval=replace(self.approval, target="DOC-ALLOWED"))
        self.assertTrue(self.verdict(intent=intent, snapshot=context).allowed)

    def test_gov_wrong_project_fails_closed(self):
        self.deny("WRONG_PROJECT", intent=replace(self.intent, project_id="MOCHIVNST"))
        self.deny("SCOPE_MISMATCH", snapshot=replace(
            self.snapshot, control=replace(self.control, project_id="OTHER")
        ))

    def test_gov_old_owner_generation_rejected_after_transfer(self):
        self.deny("STALE_OWNER_GENERATION", intent=replace(self.intent, owner_generation=6))
        self.deny("STALE_OWNER_GENERATION", snapshot=replace(self.snapshot, owner_generation=8))
        self.deny("STALE_OWNER_GENERATION", snapshot=replace(
            self.snapshot, control=replace(self.control, owner_generation=8)
        ))

    def test_gov_unauthorized_discussion_or_missing_trust(self):
        for flag in (
            "issuer_authenticated",
            "conversation_bound",
            "owner_approved_out_of_band",
            "git_writer_credential_isolated",
            "drive_writer_credential_isolated",
        ):
            with self.subTest(flag=flag):
                context = replace(
                    self.snapshot, approval=replace(self.approval, **{flag: False})
                )
                self.deny("TRUST_GATE_NOT_PROVISIONED", snapshot=context)

    def test_gov_replay_requires_atomic_nonce_reservation(self):
        self.deny("REPLAY_GUARD_MISSING", snapshot=replace(
            self.snapshot, approval=replace(self.approval, nonce_atomically_reserved=False)
        ))
        self.deny("APPROVAL_SCOPE_MISMATCH", intent=replace(self.intent, nonce="replayed-nonce"))

    def test_gov_approval_cannot_be_retargeted(self):
        for field, value in (
            ("request_id", "REQ-002"),
            ("session_id", "different-session"),
            ("work_item", "OTHER"),
            ("target", "DOC-ALLOWED"),
        ):
            with self.subTest(field=field):
                intent = replace(self.intent, **{field: value})
                expected = "APPROVAL_SCOPE_MISMATCH"
                self.deny(expected, intent=intent)

    def test_gov_free_frozen_or_unknown_lease_fails(self):
        for state in ("FREE", "FROZEN", "EXPIRED", ""):
            with self.subTest(state=state):
                self.deny("LEASE_NOT_HELD", snapshot=replace(
                    self.snapshot, lease=replace(self.lease, state=state)
                ))

    def test_gov_stale_session_epoch_and_work_item(self):
        self.deny("STALE_SESSION_OR_EPOCH", intent=replace(self.intent, lease_epoch=19))
        self.deny("STALE_SESSION_OR_EPOCH", snapshot=replace(
            self.snapshot, lease=replace(self.lease, session_id="old-chat")
        ))
        self.deny("WORK_ITEM_MISMATCH", snapshot=replace(
            self.snapshot, lease=replace(self.lease, work_item="DIFFERENT")
        ))

    def test_gov_expired_or_missing_lease_deadline(self):
        self.deny("LEASE_EXPIRED_OR_UNKNOWN", now=self.lease.expires_at)
        self.deny("LEASE_EXPIRED_OR_UNKNOWN", snapshot=replace(
            self.snapshot, lease=replace(self.lease, expires_at=None)
        ))

    def test_gov_reject_naive_utc_clock(self):
        self.deny("INVALID_CLOCK", now=datetime(2026, 11, 8, 10))
        self.deny("LEASE_EXPIRED_OR_UNKNOWN", snapshot=replace(
            self.snapshot, lease=replace(
                self.lease, expires_at=datetime(2026, 11, 8, 10, 5)
            )
        ))

    def test_gov_control_ref_frozen_unprotected_or_no_permit(self):
        variants = (
            {"protected": False},
            {"state": "FROZEN"},
            {"writer_state": "NOT_ACTIVE"},
            {"permit_write": False},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.deny("CONTROL_FROZEN_OR_UNPROTECTED", snapshot=replace(
                    self.snapshot, control=replace(self.control, **variant)
                ))

    def test_gov_git_main_or_control_drift(self):
        self.deny("GIT_HEAD_DRIFT", intent=replace(self.intent, expected_main_sha="c" * 40))
        self.deny("GIT_HEAD_DRIFT", intent=replace(self.intent, expected_control_sha="d" * 40))
        self.deny("GIT_HEAD_DRIFT", snapshot=replace(self.snapshot, main_sha="invalid"))
        self.deny("GIT_HEAD_DRIFT", snapshot=replace(
            self.snapshot, control=replace(self.control, ref_sha="malformed")
        ))

    def test_gov_exact_path_allowlist(self):
        self.deny("TARGET_OUT_OF_SCOPE", intent=replace(
            self.intent, target="secrets/token.txt"
        ))

    def test_gov_no_direct_main_or_control_commits(self):
        for branch in ("main", "control/mochifx-writer-gate", "other/branch"):
            with self.subTest(branch=branch):
                self.deny("GIT_TARGET_NOT_ALLOWED",
                          intent=replace(self.intent, branch=branch),
                          snapshot=replace(
                              self.snapshot,
                              allowed_git_branches=frozenset(
                                  {"p0/scoped", "main", "control/mochifx-writer-gate"}
                              ),
                          ))

    def test_gov_no_git_operation_with_doc_revision(self):
        self.deny("GIT_TARGET_NOT_ALLOWED", intent=replace(
            self.intent, expected_doc_revision="stale"
        ))

    def test_gov_docs_revision_must_match_cas(self):
        intent = replace(
            self.intent, action=ACTION_DOCS, target="DOC-ALLOWED",
            branch=None, expected_doc_revision="old-revision",
        )
        context = replace(self.snapshot, approval=replace(self.approval, target="DOC-ALLOWED"))
        self.deny("DOCS_REVISION_DRIFT", intent=intent, snapshot=context)
        self.deny("DOCS_REVISION_DRIFT", intent=replace(
            intent, expected_doc_revision=None
        ), snapshot=context)

    def test_gov_docs_must_not_include_git_branch(self):
        intent = replace(self.intent, action=ACTION_DOCS, target="DOC-ALLOWED",
                         expected_doc_revision="revision-expected")
        context = replace(self.snapshot, approval=replace(self.approval, target="DOC-ALLOWED"))
        self.deny("DOCS_BRANCH_NOT_ALLOWED", intent=intent, snapshot=context)

    def test_gov_unapproved_action_rejected(self):
        self.deny("UNKNOWN_ACTION", intent=replace(self.intent, action="github.admin_ruleset"))

    def test_gov_missing_request_fields_rejected(self):
        for field in ("request_id", "nonce", "session_id", "work_item", "target"):
            with self.subTest(field=field):
                self.deny("MISSING_REQUEST_FIELD", intent=replace(self.intent, **{field: "  "}))

    def test_gov_invalid_structured_inputs_rejected(self):
        self.assertEqual(evaluate(None, self.snapshot, NOW).reason, "INVALID_INPUT")
        self.assertEqual(evaluate(self.intent, None, NOW).reason, "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
