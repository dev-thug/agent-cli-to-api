#!/usr/bin/env python3
"""
Test rate limit error detection and OpenClaw failover compatibility.

This test verifies that the gateway correctly detects rate limit errors
and returns HTTP 429 with rate_limit_error type, enabling OpenClaw failover.
"""

import sys
from pathlib import Path

# Add parent to path so we can import from codex_gateway
sys.path.insert(0, str(Path(__file__).parent))

from codex_gateway.server import _openai_error


def test_rate_limit_detection():
    """Test that rate limit errors are correctly detected and transformed."""
    print("\n" + "=" * 80)
    print("TEST: Rate Limit Error Detection for OpenClaw Failover")
    print("=" * 80)
    
    test_cases = [
        # (error_message, expected_status, expected_type, expected_code, description)
        (
            "You've hit your limit · resets 6pm (Europe/Copenhagen)",
            429,
            "rate_limit_error",
            "rate_limit_exceeded",
            "Claude Code rate limit message"
        ),
        (
            "Rate limit exceeded. Please try again later.",
            429,
            "rate_limit_error",
            "rate_limit_exceeded",
            "Generic rate limit message"
        ),
        (
            "Error: Too many requests",
            429,
            "rate_limit_error",
            "rate_limit_exceeded",
            "Too many requests message"
        ),
        (
            "API quota exceeded for this billing period",
            429,
            "rate_limit_error",
            "rate_limit_exceeded",
            "Quota exceeded message"
        ),
        (
            "Usage limit reached",
            429,
            "rate_limit_error",
            "rate_limit_exceeded",
            "Usage limit message"
        ),
        (
            "Connection timeout",
            500,
            "codex_gateway_error",
            None,
            "Non-rate-limit error (should not trigger)"
        ),
        (
            "Internal server error",
            500,
            "codex_gateway_error",
            None,
            "Generic error (should not trigger)"
        ),
    ]
    
    passed = 0
    failed = 0
    
    for message, expected_status, expected_type, expected_code, description in test_cases:
        print(f"\n[Test] {description}")
        print(f"  Message: {message}")
        
        response = _openai_error(message)
        
        # Extract response data
        status_code = response.status_code
        body = response.body.decode('utf-8')
        
        # Parse JSON body
        import json
        data = json.loads(body)
        error = data.get("error", {})
        error_type = error.get("type")
        error_code = error.get("code")
        
        # Verify results
        print(f"  Expected: status={expected_status}, type={expected_type}, code={expected_code}")
        print(f"  Got:      status={status_code}, type={error_type}, code={error_code}")
        
        if (status_code == expected_status and 
            error_type == expected_type and 
            error_code == expected_code):
            print("  ✅ PASSED")
            passed += 1
        else:
            print("  ❌ FAILED")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")
        print("\nRate limit errors will now trigger OpenClaw failover:")
        print("  • HTTP 429 (Too Many Requests)")
        print("  • error.type: 'rate_limit_error'")
        print("  • error.code: 'rate_limit_exceeded'")


def test_openai_format():
    """Verify the response format matches OpenAI API."""
    print("\n" + "=" * 80)
    print("TEST: OpenAI API Format Compliance")
    print("=" * 80)
    
    import json
    
    response = _openai_error("You've hit your limit · resets 6pm (Europe/Copenhagen)")
    body = json.loads(response.body.decode('utf-8'))
    
    print("\nResponse format:")
    print(json.dumps(body, indent=2))
    
    # Verify structure
    assert "error" in body, "Response must have 'error' field"
    error = body["error"]
    
    assert "message" in error, "Error must have 'message' field"
    assert "type" in error, "Error must have 'type' field"
    assert "param" in error, "Error must have 'param' field"
    assert "code" in error, "Error must have 'code' field"
    
    assert error["type"] == "rate_limit_error", f"Expected rate_limit_error, got {error['type']}"
    assert error["code"] == "rate_limit_exceeded", f"Expected rate_limit_exceeded, got {error['code']}"
    assert response.status_code == 429, f"Expected status 429, got {response.status_code}"
    
    print("\n✅ Response format is OpenAI-compatible!")


if __name__ == "__main__":
    try:
        test_rate_limit_detection()
        test_openai_format()
        
        print("\n" + "=" * 80)
        print("🎉 ALL TESTS PASSED!")
        print("=" * 80)
        print("\nThe gateway will now correctly signal rate limits to OpenClaw,")
        print("enabling automatic failover to the next model in your fallbacks list.")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
