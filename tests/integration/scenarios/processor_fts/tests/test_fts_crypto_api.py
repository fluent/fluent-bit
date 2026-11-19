"""General hash/HMAC author APIs, including opaque key lifecycle and budgets."""
from pathlib import Path

import pytest

from test_fts_packs import authored_pack
from test_fts_recipes import config_file, rejected_startup
from test_fts_records import send, rows, log_text
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("value,digest", [
    ("", "2d06800538d394c2"),
    (b"\x00", "c44bdff4074eecdb"),
    ("fts-sample-v1:4:logs7:default1:a", "3112b48af0e0b03e"),
    ("fts-sample-v1:4:logs7:default1:b", "ee406fa1e2c3458b"),
])
def test_hash_reference_vectors_and_integer_modulus(tmp_path, value, digest):
    # XXH3 v0.8.3 upstream sanity vectors, seed zero (lengths 0 and 1).
    proc = authored_pack(tmp_path, '''return function(p)
        return function(log)
            local value=log.body:get('input'):value()
            log.body:set('digest',fb.hash64(value))
            log.body:set('modulus',fb.hash64_mod(value,10000))
            log.body:set('algorithm',fb.hash64_algorithm)
        end
    end''')
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, [{"input": value}])
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert result[0]["digest"] == digest
        assert result[0]["modulus"] == int(digest, 16) % 10000
        assert result[0]["algorithm"] == "xxh3-64-v1-seed0"
    finally:
        service.stop()


@pytest.mark.parametrize("key,message,digest", [
    ("Jefe", "what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ("\x0b" * 20, "Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
])
def test_hmac_rfc4231_opaque_key_reference(tmp_path, monkeypatch, key, message, digest):
    monkeypatch.setenv("FTS_FIXTURE_HMAC_KEY", key)
    proc = authored_pack(tmp_path, '''return function(p)
        return function(log)
            log.body:set('digest',fb.hmac_sha256('test-v1',log.body:get('input'):value()))
        end
    end''')
    proc["secret_refs"] = {"test-v1": "FTS_FIXTURE_HMAC_KEY"}
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, [{"input": message}])
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert result[0]["digest"] == digest
        assert key not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("expression,error", [
    ("fb.hash64(7)", "wrong_type"),
    ("fb.hash64_mod('x',0)", "invalid_parameter"),
    ("fb.hash64_mod('x',1.5)", "invalid_parameter"),
    ("fb.hash64_mod('x',1000000001)", "invalid_parameter"),
    ("fb.hmac_sha256('unknown','x')", "invalid_parameter"),
    ("fb.hmac_sha256(7,'x')", "wrong_type"),
])
def test_crypto_errors_rollback_edits_and_keep_control(tmp_path, expression, error):
    proc = authored_pack(tmp_path, '''return function(p)
        return function(log)
            if log.body:get('fail') then
                log.body:set('changed',true)
                ''' + expression + '''
            end
        end
    end''')
    proc["error_mode"] = "keep"
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, [{"fail": 1}, {"control": 1}])
        result = service.wait_for_condition(lambda: len(rows(service)) == 2 and rows(service), timeout=30)
        for record in result:
            record.pop("date", None)
        assert result == [{"fail": 1}, {"control": 1}]
        assert f"class={error}" in log_text(service, f"class={error}")
    finally:
        service.stop()


@pytest.mark.parametrize("references", [
    [], {"test": 7}, {"../bad": "FTS_FIXTURE_HMAC_KEY"},
    {"test": "BAD-VARIABLE"}, {"test": "FTS_FIXTURE_MISSING"},
    {f"key{i}": "FTS_FIXTURE_HMAC_KEY" for i in range(17)},
])
def test_secret_reference_configuration_rejected(tmp_path, monkeypatch, references):
    monkeypatch.setenv("FTS_FIXTURE_HMAC_KEY", "synthetic-key-never-published")
    monkeypatch.delenv("FTS_FIXTURE_MISSING", raising=False)
    proc = authored_pack(tmp_path, "return function(p) return function(log) end end")
    proc["secret_refs"] = references
    diagnostics = rejected_startup(config_file(tmp_path, proc), tmp_path)
    assert "synthetic-key-never-published" not in diagnostics


def test_oversized_key_rejected_without_disclosure(tmp_path, monkeypatch):
    secret = "synthetic-oversized-" + "x" * 4096
    monkeypatch.setenv("FTS_FIXTURE_HMAC_KEY", secret)
    proc = authored_pack(tmp_path, "return function(p) return function(log) end end")
    proc["secret_refs"] = {"test": "FTS_FIXTURE_HMAC_KEY"}
    assert secret not in rejected_startup(config_file(tmp_path, proc), tmp_path)


@pytest.mark.parametrize("operation", ["hash64", "hmac_sha256"])
def test_native_hash_work_cannot_bypass_instruction_budget(tmp_path, monkeypatch, operation):
    monkeypatch.setenv("FTS_FIXTURE_HMAC_KEY", "public-budget-test-key")
    expression = "fb.hash64(value)" if operation == "hash64" else "fb.hmac_sha256('test-v1',value)"
    proc = authored_pack(tmp_path, '''return function(p)
        return function(log)
            if log.body:get('fail') then
                log.body:set('changed',true)
                local value=string.rep('x',65536)
                for i=1,20 do ''' + expression + ''' end
            end
        end
    end''')
    proc.update(error_mode="keep", instruction_limit=40000,
        secret_refs={"test-v1": "FTS_FIXTURE_HMAC_KEY"})
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, [{"fail": 1}, {"control": 1}])
        result = service.wait_for_condition(lambda: len(rows(service)) == 2 and rows(service), timeout=30)
        for record in result:
            record.pop("date", None)
        assert result == [{"fail": 1}, {"control": 1}]
        assert "class=budget_exceeded" in log_text(service, "class=budget_exceeded")
    finally:
        service.stop()
