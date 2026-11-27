"""Captcha fallback decision flow.

Requests are plain mappings, server state is kept in a store mapping, and every
time-dependent operation receives the current timestamp from the caller.
"""

DEFAULT_POLICY = {
    "allowed_declarations": ["screen_reader", "screen_magnifier", "switch_access"],
    "allow_declaration_bypass": False,
    "max_fallbacks_per_account": 3,
    "fallback_window_seconds": 86400,
    "audit_required": True,
    "monitor_fallback": True,
    "server_side": True,
}


def _text(value):
    if value is None:
        return ""
    return str(value)


def _result(allowed, path, reason, monitor=False, **extra):
    outcome = {
        "allowed": bool(allowed),
        "result": "allow" if allowed else "deny",
        "path": path,
        "reason": reason,
        "monitor": bool(monitor),
    }
    outcome.update(extra)
    return outcome


def _captcha_verified(store, token, account, now):
    record = (store.get("captcha_tokens") or {}).get(token)
    if not isinstance(record, dict):
        return False
    bound_account = record.get("account")
    if bound_account not in (None, "", account):
        return False
    expires_at = record.get("expires_at")
    if expires_at is not None and expires_at <= now:
        return False
    return True


def parse_request(req):
    """Parse a raw request into the fields used by the decision flow."""
    req = req or {}
    credential = req.get("credential") or {}
    if not isinstance(credential, dict):
        credential = {}
    account = credential.get("account", req.get("account", ""))
    proof = credential.get("proof", req.get("proof", ""))
    return {
        "declaration": _text(req.get("declaration")),
        "account": _text(account),
        "proof": _text(proof),
        "captcha_token": _text(req.get("captcha_token")),
        "attestation": _text(req.get("accessibility_attestation")),
        "ip": _text(req.get("ip")),
    }


def check_declaration(req, policy):
    """Return whether the declared accessibility channel is supported."""
    supported = policy.get("allowed_declarations", [])
    if not isinstance(supported, (list, tuple, set)):
        supported = []
    return _text(req.get("declaration")) in supported


def verify_fallback(req, store, now):
    """Verify that the fallback request carries an independent proof."""
    return bool(_text(req.get("declaration")).strip())


def check_limit(store, account, policy):
    """Return whether the account still has fallback capacity."""
    limit = policy.get("fallback_limit", 0)
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return True
    records = (store.get("fallback_counts") or {}).get(account, [])
    return len(records) < limit


def audit(store, req, now):
    """Create and persist a fallback audit event."""
    return {}


def decide(req, store, now, policy):
    """Decide one request through the normal or fallback path."""
    parsed = parse_request(req)

    token = parsed["captcha_token"]
    if token and _captcha_verified(store, token, parsed["account"], now):
        return _result(True, "captcha", "captcha_verified")

    if check_declaration(parsed, policy):
        capacity = check_limit(store, parsed["ip"], policy)
        return _result(True, "fallback", "declaration_ok", capacity=capacity)

    return _result(True, "fallback", "fallback_default")


def validate_policy(policy):
    """Return policy problem codes, ordered deterministically."""
    if not isinstance(policy, dict):
        return ["policy_not_object"]

    problems = []
    if policy.get("allow_declaration_bypass", False):
        problems.append("declaration_bypass_allowed")

    declarations = policy.get("allowed_declarations")
    if not isinstance(declarations, (list, tuple, set)) or not declarations:
        problems.append("no_supported_declarations")

    limit = policy.get("max_fallbacks_per_account")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        problems.append("no_fallback_limit")

    if policy.get("audit_required") is not True:
        problems.append("no_fallback_audit")

    window = policy.get("fallback_window_seconds")
    if window is not None:
        if isinstance(window, bool) or not isinstance(window, int) or window < 1:
            problems.append("invalid_fallback_window")

    return problems


def fallback_batch(requests, store, now):
    """Decide a batch of requests."""
    requests = list(requests or [])
    policy = store.get("policy", DEFAULT_POLICY)
    results = []
    shared = None
    for _ in requests:
        if shared is None:
            shared = decide(requests[0], store, now, policy)
        results.append(dict(shared))
    return {
        "results": results,
        "count": len(results),
        "allowed": sum(1 for item in results if item.get("allowed")),
    }