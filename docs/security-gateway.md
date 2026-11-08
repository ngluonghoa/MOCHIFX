# MOCHIFX P0 — Trusted Write Gateway reference specification

Status: REFERENCE IMPLEMENTATION ONLY; REMOTE ENFORCEMENT BLOCKED.
Scope: MOCHIFX only. This document confers no permission to edit MOCHIVNST.

## 1. Threat model and existing controls

An old or parallel ChatGPT conversation can invoke the same owner-authorized
GitHub / Google Drive connector as the official chat, regardless of written
instructions. A manual chat label cannot cryptographically identify a client.

- Main is protected by pull requests, squash, and required Python 3.11/3.12 checks.
- The separate control ref has update/deletion/force-push restrictions and no
  bypass. It remains FROZEN / NOT_ACTIVE / permit_write=false.
- The canonical administrative owner is generation 1; work leases are frozen
  between narrow authorized governance tasks.
- The MOCHIFX Docs and folder show owner-only sharing, but the existing
  owner OAuth connection is STILL a direct writer usable by other chats.
- An independent session authentication service, isolated writer credentials,
  trusted gateway, transaction/nonce ledger and real cross-actor denial
  evidence do not yet exist.

No policy-unit-test PASS should be called REMOTE_ENFORCED.

## 2. Required security boundary

A trusted service external to chat instructions must own the only privileged
credentials and authenticate out-of-band owner approval. ChatGPT clients may
submit a proposal but never construct their own authorization proof.

Before each mutation, the independent service must verify:

1. Owner identity authenticated by a separate trusted channel. Approval is
   explicitly bound to project, request ID, operation, target, work item, expiry.
2. A short-lived, genuine session capability; the current owner generation
   matches and a previous chat has been revoked by controlled transfer.
3. Current lease is HELD, correctly scoped, unexpired; the protected control
   record agrees with the owner generation and actively permits writing.
4. Actual GitHub main/control head SHAs and exact allowlisted branch/file scope
   match the approved operation. Never write directly to main/control as client.
5. The approved Docs ID and requiredRevisionId equal the current trusted
   Google Docs revision; no permissive merge revision fallback.
6. A transactional backend atomically reserves a one-time request/nonce and
   serializes writers; retries and two competing writers are refused.
7. Service credentials and protected-ref bypass, if configured, are limited
   to the trusted service and cannot be obtained by untrusted PRs/chats.
8. Tamper-evident or separately governed receipts capture the operation,
   external approver, actor, SHA/revision, result and denial reason.

## 3. Scope of the accompanying Python code

The module governance_gateway/policy.py is a PURE, SIDE-EFFECT-FREE reference
policy. It performs a fail-closed preflight over injected data ONLY.
It DOES NOT authenticate a ChatGPT conversation, validate a cryptographic
signature, fetch provider state, atomically reserve a nonce, issue a token,
execute GitHub CAS, or edit Docs.

Its VerifiedApproval dataclass can be freely fabricated by a Python caller.
A real gateway must construct that object only AFTER a trusted server has
independently verified all claims; never expose this module as an authority
to a chat client. Positive unit tests simulate hypothetical attestations.

## 4. Future privileged transaction protocol (NOT implemented)

1. Receive an authenticated, single-use request through a controlled service.
2. Verify owner approval and session identity; transactionally check owner,
   work lease, scope and unused nonce. Reserve the nonce under exclusive lock.
3. Re-read GitHub and Google Docs from the service identity and compare exact
   remote HEAD SHA, control state and Docs revision.
4. Execute only the reviewed small operation. Git source goes through a
   protected Pull Request, and Docs edits use requiredRevisionId CAS.
5. Re-read the remote outcome; append an independently auditable receipt.
6. Any partially successful Git/Docs sequence enters FROZEN / RECONCILE.
   GitHub and Google Docs are not one atomic transaction, so never silently
   repeat a destructive operation after a partial response.

The previous stale GitHub update_ref experiment failed with an opaque GraphQL
error and unchanged ref; this DOES NOT prove correct CAS conflict handling.
Test exact expected-head semantics with two independent disposable actors.

## 5. Prerequisites requiring explicit owner configuration

GitHub: Provision a dedicated least-privilege GitHub App or other trusted
service principal scoped to MOCHIFX. The control branch stays fully update
restricted with no bypass until that actor is deployed and approved. Never
allow a human, all Actions jobs or every ChatGPT chat as a broad bypass.
Privileged workflows must originate from reviewed protected code; GitHub
environment reviewers can be an additional approval gate, not the sole trust
mechanism.

Google Drive: Existing canonical Docs are owned by the account currently
connected to ChatGPT. Adding a gateway service account as a second writer
does NOT revoke existing owner-based writes from old conversations. Before
claiming isolation, plan an independently controlled document owner or a
Workspace-managed sharing boundary, provision a restricted gateway writer,
verify backups/restoration and safely migrate ChatGPT to a READ-ONLY identity.
Do not transfer Docs ownership or revoke existing access before recovery
and permissions are independently proven.

Session: Current GitHub/Drive connectors do not attest a specific ChatGPT
conversation ID. Conversation labels, prompts and a supplied Boolean are not
authentication. Without an independent owner-bound session capability, DENY.

## 6. Acceptance gates

The GitHub Actions reference workflow runs synthetic, dependency-free policy
tests on Python 3.11 and 3.12. It uses read-only permissions, SHA-pinned
first-party actions, no secrets and no privileged mutation.

Synthetic tests exercise owner generation changes, old sessions, conflicting
or expired leases, wrong project, absent approval, nonce reuse not blocked,
frozen/unprotected control ref, mismatched Git heads and Docs revisions,
out-of-scope paths and direct-main/control attempts.

GOV-01..GOV-10 and T01..T18 remain BLOCKED until isolated test identities,
disposable repositories/Docs, real denial responses and before/after
readbacks are independently collected and reviewed.

## 7. Invariants and rollback

- This PR is draft-only initially; no auto-merge or live service deployment.
- The real Git control record stays FROZEN and permit_write=false.
- The Google Docs OAuth owner connection remains unsafe against sibling chats
  until its direct write capability is truly removed by a safe migration.
- No Forex M0.3 trading source, broker/provider operation or MOCHIVNST edit.
- Revert this isolated reference PR squash commit if later rejected; this
  never implies rollback of any Google Drive or real-service operation.
- PR-001 is a separate, atomic PR scope.
