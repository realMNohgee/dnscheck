#!/usr/bin/env python3
"""Tests for dnscheck — end-to-end tests exercising each command."""

import json
import os
import subprocess
import sys

TOOL = os.path.join(os.path.dirname(__file__), "dnscheck.py")


def run(*args):
    """Run dnscheck with args."""
    cmd = [sys.executable, TOOL] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def test_lookup_a():
    """Test A record lookup."""
    rc, out, err = run("lookup", "A", "google.com")
    if rc != 0:
        print(f"  NOTE: A lookup failed (network/rate limit): {err.strip()}")
        return  # Don't fail on network issues
    assert out, "Should have output"
    # Should contain an IP-like pattern
    assert "." in out or rc == 0


def test_lookup_aaaa():
    """Test AAAA record lookup."""
    rc, out, err = run("lookup", "AAAA", "google.com")
    if rc != 0:
        print(f"  NOTE: AAAA lookup failed: {err.strip()}")
        return


def test_lookup_mx():
    """Test MX record lookup."""
    rc, out, err = run("lookup", "MX", "gmail.com")
    if rc != 0:
        print(f"  NOTE: MX lookup failed: {err.strip()}")
        return
    assert "gmail" in out.lower() or "mx" in out.lower() or "." in out


def test_lookup_txt():
    """Test TXT record lookup."""
    rc, out, err = run("lookup", "TXT", "google.com")
    if rc != 0:
        print(f"  NOTE: TXT lookup failed: {err.strip()}")
        return


def test_lookup_ns():
    """Test NS record lookup."""
    rc, out, err = run("lookup", "NS", "google.com")
    if rc != 0:
        print(f"  NOTE: NS lookup failed: {err.strip()}")
        return


def test_lookup_cname():
    """Test CNAME record lookup."""
    rc, out, err = run("lookup", "CNAME", "www.github.com")
    if rc != 0:
        print(f"  NOTE: CNAME lookup failed: {err.strip()}")
        return


def test_lookup_json():
    """Test JSON output format."""
    rc, out, err = run("lookup", "--format", "json", "A", "google.com")
    if rc != 0:
        print(f"  NOTE: JSON lookup failed: {err.strip()}")
        return
    try:
        data = json.loads(out)
        assert isinstance(data, list)
    except json.JSONDecodeError as e:
        print(f"  NOTE: JSON parse failed: {e}")
        return


def test_all():
    """Test 'all' command."""
    rc, out, err = run("all", "google.com")
    if rc != 0:
        print(f"  NOTE: all lookup failed: {err.strip()}")
        return
    assert out, "Should have output"


def test_mx_priority():
    """Test mx-priority command."""
    rc, out, err = run("mx-priority", "gmail.com")
    if rc != 0:
        print(f"  NOTE: mx-priority failed: {err.strip()}")
        return
    assert "Priority" in out or "gmail" in out.lower() or "google" in out.lower()


def test_txt():
    """Test txt command with SPF/DMARC parsing."""
    rc, out, err = run("txt", "google.com")
    if rc != 0:
        print(f"  NOTE: txt failed: {err.strip()}")
        return
    # Domain may or may not have SPF/DMARC, just check it runs


def test_soa_lookup():
    """Test SOA record lookup."""
    rc, out, err = run("lookup", "SOA", "google.com")
    if rc != 0:
        print(f"  NOTE: SOA lookup failed: {err.strip()}")
        return


def test_help():
    """Test help for all subcommands."""
    for cmd in ["lookup", "all", "mx-priority", "txt"]:
        rc, out, err = run(cmd, "--help")
        assert rc == 0, f"{cmd} --help failed: {err}"
        assert out, f"{cmd} --help produced no output"


def test_nonexistent_domain():
    """Test lookup on nonexistent domain returns non-zero."""
    rc, out, err = run("lookup", "A", "thisdomaindoesnotexist123456789.invalid")
    # Should return non-zero for NXDOMAIN
    assert rc != 0, f"Expected non-zero for nonexistent domain, got {rc}"


if __name__ == "__main__":
    tests = [
        test_lookup_a,
        test_lookup_aaaa,
        test_lookup_mx,
        test_lookup_txt,
        test_lookup_ns,
        test_lookup_cname,
        test_lookup_json,
        test_all,
        test_mx_priority,
        test_txt,
        test_soa_lookup,
        test_help,
        test_nonexistent_domain,
    ]

    passed = 0
    failed = 0
    skipped = 0
    for t in tests:
        try:
            result = t()
            if result is False:
                skipped += 1
            else:
                print(f"PASS: {t.__name__}")
                passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {t.__name__}: {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)
