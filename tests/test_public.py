from captchafb.flow import (
    check_declaration,
    check_limit,
    fallback_batch,
    parse_request,
    verify_fallback,
)

NOW = 1_800_000_000


def _policy(**overrides):
    policy = {
        "allowed_declarations": ["screen_reader", "screen_magnifier"],
        "allow_declaration_bypass": False,
        "max_fallbacks_per_account": 2,
        "fallback_window_seconds": 3600,
        "audit_required": True,
        "monitor_fallback": True,
        "server_side": True,
    }
    policy.update(overrides)
    return policy


def _store(policy):
    return {
        "policy": policy,
        "captcha_tokens": {},
        "attestations": {},
        "fallback_counts": {},
        "audit_log": [],
        "monitored_accounts": [],
    }


def test_parse_request_normalizes_fields():
    parsed = parse_request(
        {
            "declaration": "  Screen_Reader  ",
            "credential": {"account": " alice ", "proof": " secret "},
            "captcha_token": " cap-1 ",
            "accessibility_attestation": " att-1 ",
            "ip": " 198.51.100.10 ",
        }
    )

    assert parsed["declaration"] == "screen_reader"
    assert parsed["account"] == "alice"
    assert parsed["proof"] == "secret"
    assert parsed["captcha_token"] == "cap-1"
    assert parsed["attestation"] == "att-1"
    assert parsed["ip"] == "198.51.100.10"


def test_declaration_requires_more_than_itself():
    policy = _policy()

    assert check_declaration({"declaration": "screen_reader"}, policy) is False
    assert (
        check_declaration(
            {
                "declaration": "screen_reader",
                "credential": {"account": "alice", "proof": "secret"},
            },
            policy,
        )
        is True
    )


def test_fallback_requires_independent_attestation():
    store = _store(_policy())
    request = {
        "declaration": "screen_reader",
        "credential": {"account": "alice", "proof": "secret"},
    }

    assert verify_fallback(request, store, NOW) is False

    store["attestations"]["att-1"] = {
        "account": "alice",
        "declaration": "screen_reader",
        "expires_at": NOW + 60,
        "verified": True,
    }
    request["accessibility_attestation"] = "att-1"
    assert verify_fallback(request, store, NOW) is True


def test_check_limit_blocks_account_at_cap():
    policy = _policy(max_fallbacks_per_account=2)
    store = _store(policy)
    store["fallback_counts"]["alice"] = [NOW - 30, NOW - 10]

    assert check_limit(store, "alice", policy) is False
    assert check_limit(store, "bob", policy) is True


def test_batch_keeps_each_request_independent():
    policy = _policy()
    store = _store(policy)
    store["attestations"]["att-1"] = {
        "account": "alice",
        "declaration": "screen_reader",
        "expires_at": NOW + 60,
        "verified": True,
    }
    requests = [
        {
            "declaration": "screen_reader",
            "credential": {"account": "alice", "proof": "secret"},
            "accessibility_attestation": "att-1",
            "ip": "198.51.100.10",
        },
        {
            "credential": {"account": "bob", "proof": "secret"},
            "ip": "198.51.100.11",
        },
    ]

    result = fallback_batch(requests, store, NOW)

    assert result["count"] == 2
    assert result["results"][0]["allowed"] is True
    assert result["results"][1]["allowed"] is False
    assert result["allowed"] == 1