"""Self-test for the WS1-7 credential-header anchor mirror.

The mirror decides Task 27 R1 with a number, so it has to agree with the code
it mirrors. Every expectation below was READ OFF the live Rust detector, not
reasoned about: each string was run through `DetectorRegistry::detect` and the
verdict recorded is whether the emitted `bearer_token` span extends past the
needle (the value is redacted) or stops at it (label-only -- the value ships in
the clear). The nine strings and their verdicts:

    ACCEPT  curl -H "Authorization: Bearer <tok>"
    REJECT  sudo "Authorization: Bearer <tok>"
    REJECT  - Authorization: Bearer <tok>
    REJECT  steps:\\n  - Authorization: Bearer <tok>
    REJECT  The "Authorization:" Bearer <tok> scheme.
    ACCEPT  Note: Authorization: Bearer <tok>
    ACCEPT  Authorization: Bearer <tok>
    ACCEPT  headers: { "Authorization": "Bearer <tok>"
    ACCEPT  GET /x HTTP/1.1\\nAuthorization: Bearer <tok>

The same mirror was additionally cross-checked against the detector over all
273 labelled occurrences in the developer-text population: 273/273 agreed.
"""
from __future__ import annotations

import measure_auth_header_anchor as m

TOKEN = "tok999abcdef"


def verdicts(snippet: str):
    """`(accepted_today, accepted_under_proposal)` for the first `Bearer `."""
    at = snippet.find("Bearer ")
    assert at != -1, "premise: the fixture must contain the needle"
    today, proposed, _prefix, _suffix, _ls, _yd, _eq = m.gate(snippet, at)
    return today, proposed


# ── the mirror must reproduce the detector, accept and reject alike ──────────

def test_curl_dash_h_is_accepted_today_because_fu6_closed_it():
    # Half of R1 is already fixed. A measurement that reported it as still
    # leaking would inflate the case for changing the gate again.
    assert verdicts(f'curl -H "Authorization: Bearer {TOKEN}"')[0] is True


def test_a_plain_word_before_the_header_is_still_rejected():
    # POSITIVE CONTROL that must differ from curl: same shape, `sudo` instead
    # of the flag. If this were also accepted, the flag list would not be doing
    # the work and the curl result above would prove nothing.
    assert verdicts(f'sudo "Authorization: Bearer {TOKEN}"')[0] is False


def test_the_yaml_sequence_dash_is_the_open_half_of_r1():
    for snippet in (
        f"- Authorization: Bearer {TOKEN}",
        f"steps:\n  - Authorization: Bearer {TOKEN}",
    ):
        today, proposed = verdicts(snippet)
        assert today is False, f"{snippet!r} must still leak today"
        assert proposed is True, f"{snippet!r} is what the R1 proposal exists to close"


def test_the_prose_mention_stays_rejected_under_the_proposal():
    # The direction earlier rounds oscillated on. A proposal that flipped this
    # would be re-shipping what round 4 had to take back, so BOTH verdicts are
    # asserted, not just today's.
    today, proposed = verdicts(f'The "Authorization:" Bearer {TOKEN} scheme.')
    assert today is False
    assert proposed is False, "the proposal must not readmit the round-3 prose defect"


def test_already_accepted_shapes_are_untouched_by_the_proposal():
    # The proposal is additive: anything accepted today must stay accepted, or
    # it is a regression dressed up as a fix.
    for snippet in (
        f"Note: Authorization: Bearer {TOKEN}",
        f"Authorization: Bearer {TOKEN}",
        f'headers: {{ "Authorization": "Bearer {TOKEN}"',
        f"GET /x HTTP/1.1\nAuthorization: Bearer {TOKEN}",
    ):
        today, proposed = verdicts(snippet)
        assert today is True, f"{snippet!r} is accepted by the live detector"
        assert proposed is True, f"the proposal must not withdraw {snippet!r}"


def test_a_bare_needle_with_no_header_label_is_not_gated_at_all():
    # PREMISE the whole population count rests on: 431 of the 704 needle
    # occurrences have no Authorization label, and the gate must report them as
    # unlabelled rather than as rejections -- otherwise the leak count is
    # inflated sixfold.
    at = "the Bearer scheme is described in RFC 6750".find("Bearer ")
    assert m.gate("the Bearer scheme is described in RFC 6750", at)[0] is None


# ── the mirrored stripper ────────────────────────────────────────────────────

def test_a_valid_obs_fold_is_dropped_but_a_real_line_break_clears():
    # Both halves, because the clear-on-newline is what lets a SECOND header on
    # its own line be recognised with an empty prefix.
    assert m.strip_connectors('headers: {\n  "Authorization": ') == "headers:{Authorization:"
    assert m.strip_connectors("Bearer A\nProxy-Authorization: ") == "Proxy-Authorization:"
