"""Fail-closed *reference policy*, NOT an authentication or remote write gateway.

Inputs named "verified" must come from an independent trusted server. A ChatGPT
message, GitHub branch, or JSON field is never sufficient evidence by itself.
This module has no network, filesystem, credential, or mutation capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Mapping

PROJECT_ID = "MOCHIFX"
CONTROL_BRANCH = "control/mochifx-writer-gate"
MAIN_BRANCH = "main"
ACTION_GIT = "github.branch_commit"
ACTION_DOCS = "google_docs.batch_update"
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class Intent:
    project_id: str
    action: str
    request_id: str
    nonce: str
    owner_generation: int
    lease_epoch: int
    session_id: str
    work_item: str
    target: str
    expected_main_sha: str
    expected_control_sha: str
    branch: str | None = None
    expected_doc_revision: str | None = None


@dataclass(frozen=True)
class LeaseSnapshot:
    project_id: str
    state: str
    owner_generation: int
    epoch: int
    session_id: str | None
    work_item: str | None
    expires_at: datetime | None


@dataclass(frozen=True)
class ControlSnapshot:
    project_id: str
    ref_sha: str
    state: str
    writer_state: str
    permit_write: bool
    protected: bool
    owner_generation: int


@dataclass(frozen=True)
class VerifiedApproval:
    """A trusted gateway MUST attest these fields; never deserialize untrusted JSON here."""

    issuer_authenticated: bool
    conversation_bound: bool
    owner_approved_out_of_band: bool
    git_writer_credential_isolated: bool
    drive_writer_credential_isolated: bool
    nonce_atomically_reserved: bool
    request_id: str
    nonce: str
    session_id: str
    work_item: str
    target: str


@dataclass(frozen=True)
class TrustedSnapshot:
    owner_generation: int
    lease: LeaseSnapshot
    control: ControlSnapshot
    main_sha: str
    allowed_targets: frozenset[str]
    allowed_git_branches: frozenset[str]
    docs_revisions: Mapping[str, str]
    approval: VerifiedApproval


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def deny(reason: str) -> Decision:
    return Decision(False, reason)


def _valid_sha(value: str) -> bool:
    return isinstance(value, str) and _SHA_RE.fullmatch(value) is not None


def _valid_timestamp(value: datetime | None) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def evaluate(intent: Intent, context: TrustedSnapshot, now: datetime) -> Decision:
    """Pure preflight. The adapter MUST recheck/commit atomically at the write boundary.

    This function does NOT prove identity, reserve nonces, validate provider tokens,
    perform Git compare-and-swap, or issue Google Docs requiredRevisionId writes.
    """
    if not isinstance(intent, Intent) or not isinstance(context, TrustedSnapshot):
        return deny("INVALID_INPUT")
    if not _valid_timestamp(now):
        return deny("INVALID_CLOCK")
    if intent.project_id != PROJECT_ID:
        return deny("WRONG_PROJECT")
    if intent.action not in (ACTION_GIT, ACTION_DOCS):
        return deny("UNKNOWN_ACTION")
    if not all(
        isinstance(s, str) and bool(s.strip())
        for s in (intent.request_id, intent.nonce, intent.session_id, intent.work_item, intent.target)
    ):
        return deny("MISSING_REQUEST_FIELD")
    if intent.target not in context.allowed_targets:
        return deny("TARGET_OUT_OF_SCOPE")

    evidence = context.approval
    if not isinstance(evidence, VerifiedApproval):
        return deny("UNTRUSTED_EVIDENCE")
    if not all(
        (
            evidence.issuer_authenticated,
            evidence.conversation_bound,
            evidence.owner_approved_out_of_band,
            evidence.git_writer_credential_isolated,
            evidence.drive_writer_credential_isolated,
        )
    ):
        return deny("TRUST_GATE_NOT_PROVISIONED")
    if not evidence.nonce_atomically_reserved:
        return deny("REPLAY_GUARD_MISSING")
    if (
        evidence.request_id != intent.request_id
        or evidence.nonce != intent.nonce
        or evidence.session_id != intent.session_id
        or evidence.work_item != intent.work_item
        or evidence.target != intent.target
    ):
        return deny("APPROVAL_SCOPE_MISMATCH")

    lease, control = context.lease, context.control
    if not isinstance(lease, LeaseSnapshot) or not isinstance(control, ControlSnapshot):
        return deny("INVALID_SNAPSHOT")
    if lease.project_id != PROJECT_ID or control.project_id != PROJECT_ID:
        return deny("SCOPE_MISMATCH")
    if (
        intent.owner_generation != context.owner_generation
        or context.owner_generation != lease.owner_generation
        or context.owner_generation != control.owner_generation
    ):
        return deny("STALE_OWNER_GENERATION")
    if lease.state != "HELD":
        return deny("LEASE_NOT_HELD")
    if lease.epoch != intent.lease_epoch or lease.session_id != intent.session_id:
        return deny("STALE_SESSION_OR_EPOCH")
    if lease.work_item != intent.work_item:
        return deny("WORK_ITEM_MISMATCH")
    if not _valid_timestamp(lease.expires_at) or now >= lease.expires_at:
        return deny("LEASE_EXPIRED_OR_UNKNOWN")
    if not control.protected or control.state != "ACTIVE" or control.writer_state != "HELD" or control.permit_write is not True:
        return deny("CONTROL_FROZEN_OR_UNPROTECTED")
    if not (
        _valid_sha(context.main_sha)
        and _valid_sha(control.ref_sha)
        and intent.expected_main_sha == context.main_sha
        and intent.expected_control_sha == control.ref_sha
    ):
        return deny("GIT_HEAD_DRIFT")

    if intent.action == ACTION_GIT:
        if (
            not isinstance(intent.branch, str)
            or intent.branch not in context.allowed_git_branches
            or intent.branch in (MAIN_BRANCH, CONTROL_BRANCH)
            or intent.expected_doc_revision is not None
        ):
            return deny("GIT_TARGET_NOT_ALLOWED")
    else:
        if intent.branch is not None:
            return deny("DOCS_BRANCH_NOT_ALLOWED")
        current_revision = context.docs_revisions.get(intent.target)
        if (
            not isinstance(intent.expected_doc_revision, str)
            or not intent.expected_doc_revision
            or not isinstance(current_revision, str)
            or intent.expected_doc_revision != current_revision
        ):
            return deny("DOCS_REVISION_DRIFT")

    return Decision(True, "POLICY_PREFLIGHT_ONLY")
