#!/usr/bin/env python3
"""
Test cursor-agent token usage extraction.

This test verifies that agent-cli-to-api correctly extracts and reports
token usage from cursor-agent, including cache read/write tokens.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add parent to path so we can import from codex_gateway
sys.path.insert(0, str(Path(__file__).parent))

from codex_gateway.stream_json_cli_stdin import (
    extract_usage_from_cursor_agent_result,
    TextAssembler,
    extract_cursor_agent_delta,
)


def test_cursor_agent_usage_extraction():
    """Test that cursor-agent usage is correctly extracted."""
    print("\n" + "=" * 80)
    print("TEST: Cursor-agent token usage extraction")
    print("=" * 80)
    
    # Test 1: Basic usage extraction (no cache)
    print("\n[Test 1] Basic usage (no cache)")
    evt = {
        "type": "result",
        "result": "Task completed successfully",
        "usage": {
            "inputTokens": 150,
            "outputTokens": 75,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        }
    }
    
    usage = extract_usage_from_cursor_agent_result(evt)
    print(f"Input event: {json.dumps(evt, indent=2)}")
    print(f"Extracted usage: {json.dumps(usage, indent=2)}")
    
    assert usage is not None, "Usage should not be None"
    assert usage["prompt_tokens"] == 150, f"Expected 150 prompt_tokens, got {usage['prompt_tokens']}"
    assert usage["completion_tokens"] == 75, f"Expected 75 completion_tokens, got {usage['completion_tokens']}"
    assert usage["total_tokens"] == 225, f"Expected 225 total_tokens, got {usage['total_tokens']}"
    assert "prompt_tokens_details" not in usage, "Should not have cache details when cache is 0"
    print("✅ Basic usage extraction works correctly")
    
    # Test 2: Usage with cache read
    print("\n[Test 2] Usage with cache read")
    evt = {
        "type": "result",
        "result": "Response with cached context",
        "usage": {
            "inputTokens": 100,
            "outputTokens": 50,
            "cacheReadTokens": 1500,
            "cacheWriteTokens": 0
        }
    }
    
    usage = extract_usage_from_cursor_agent_result(evt)
    print(f"Input event: {json.dumps(evt, indent=2)}")
    print(f"Extracted usage: {json.dumps(usage, indent=2)}")
    
    assert usage is not None, "Usage should not be None"
    assert usage["prompt_tokens"] == 100
    assert usage["completion_tokens"] == 50
    assert usage["total_tokens"] == 150
    assert "prompt_tokens_details" in usage, "Should have cache details"
    assert usage["prompt_tokens_details"]["cached_tokens"] == 1500
    assert "cache_creation_input_tokens" not in usage, "Should not have cache write when 0"
    print("✅ Cache read tokens extracted correctly")
    
    # Test 3: Usage with cache write
    print("\n[Test 3] Usage with cache write")
    evt = {
        "type": "result",
        "result": "Response creating new cache",
        "usage": {
            "inputTokens": 200,
            "outputTokens": 100,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 2000
        }
    }
    
    usage = extract_usage_from_cursor_agent_result(evt)
    print(f"Input event: {json.dumps(evt, indent=2)}")
    print(f"Extracted usage: {json.dumps(usage, indent=2)}")
    
    assert usage is not None
    assert usage["prompt_tokens"] == 200
    assert usage["completion_tokens"] == 100
    assert usage["total_tokens"] == 300
    assert "prompt_tokens_details" in usage
    assert usage["prompt_tokens_details"]["cached_tokens"] == 0
    assert usage["cache_creation_input_tokens"] == 2000
    print("✅ Cache write tokens extracted correctly")
    
    # Test 4: Usage with both cache read and write
    print("\n[Test 4] Usage with cache read AND write")
    evt = {
        "type": "result",
        "result": "Complex response",
        "usage": {
            "inputTokens": 300,
            "outputTokens": 150,
            "cacheReadTokens": 5000,
            "cacheWriteTokens": 1000
        }
    }
    
    usage = extract_usage_from_cursor_agent_result(evt)
    print(f"Input event: {json.dumps(evt, indent=2)}")
    print(f"Extracted usage: {json.dumps(usage, indent=2)}")
    
    assert usage is not None
    assert usage["prompt_tokens"] == 300
    assert usage["completion_tokens"] == 150
    assert usage["total_tokens"] == 450
    assert usage["prompt_tokens_details"]["cached_tokens"] == 5000
    assert usage["cache_creation_input_tokens"] == 1000
    print("✅ Both cache read and write tokens extracted correctly")
    
    # Test 5: Non-result events should return None
    print("\n[Test 5] Non-result events")
    evt = {
        "type": "assistant",
        "message": {
            "content": "Some response"
        }
    }
    
    usage = extract_usage_from_cursor_agent_result(evt)
    print(f"Input event: {json.dumps(evt, indent=2)}")
    print(f"Extracted usage: {usage}")
    
    assert usage is None, "Non-result events should return None"
    print("✅ Non-result events correctly return None")
    
    # Test 6: Missing usage field
    print("\n[Test 6] Result without usage field")
    evt = {
        "type": "result",
        "result": "No usage data"
    }
    
    usage = extract_usage_from_cursor_agent_result(evt)
    print(f"Input event: {json.dumps(evt, indent=2)}")
    print(f"Extracted usage: {usage}")
    
    assert usage is None, "Events without usage should return None"
    print("✅ Missing usage field handled correctly")
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS PASSED!")
    print("=" * 80)
    print("\nSummary:")
    print("  • Basic usage extraction works")
    print("  • Cache read tokens are captured in prompt_tokens_details")
    print("  • Cache write tokens are captured in cache_creation_input_tokens")
    print("  • Both cache operations can be tracked simultaneously")
    print("  • Non-result events correctly return None")
    print("  • Missing usage data handled gracefully")


async def test_cursor_agent_stream_simulation():
    """Simulate a cursor-agent stream with multiple events."""
    print("\n" + "=" * 80)
    print("TEST: Simulated cursor-agent stream")
    print("=" * 80)
    
    # Simulate a sequence of events from cursor-agent
    events = [
        {
            "type": "system",
            "subtype": "init",
            "model": "claude-sonnet-4",
            "apiKeySource": "user",
            "permissionMode": "auto",
            "session_id": "test-session-123"
        },
        {
            "type": "assistant",
            "message": {
                "content": "I'll help you with that. "
            }
        },
        {
            "type": "assistant",
            "message": {
                "content": "I'll help you with that. Let me analyze the code first."
            }
        },
        {
            "type": "assistant",
            "message": {
                "content": "I'll help you with that. Let me analyze the code first. I can see the issue is in the token extraction logic."
            }
        },
        {
            "type": "result",
            "result": "I'll help you with that. Let me analyze the code first. I can see the issue is in the token extraction logic.",
            "usage": {
                "inputTokens": 2500,
                "outputTokens": 150,
                "cacheReadTokens": 14570,
                "cacheWriteTokens": 0
            }
        }
    ]
    
    assembler = TextAssembler()
    usage = None
    
    print("\nProcessing events:")
    for i, evt in enumerate(events, 1):
        print(f"\n[Event {i}] Type: {evt.get('type')}")
        
        # Extract delta
        delta = extract_cursor_agent_delta(evt, assembler)
        if delta:
            print(f"  Delta: {repr(delta)}")
        
        # Extract usage
        maybe_usage = extract_usage_from_cursor_agent_result(evt)
        if maybe_usage:
            usage = maybe_usage
            print(f"  Usage: {json.dumps(usage, indent=4)}")
    
    print("\n" + "-" * 80)
    print("Final results:")
    print(f"  Assembled text: {repr(assembler.text)}")
    print(f"  Total tokens: {usage['total_tokens'] if usage else 'N/A'}")
    print(f"  Prompt tokens: {usage['prompt_tokens'] if usage else 'N/A'}")
    print(f"  Completion tokens: {usage['completion_tokens'] if usage else 'N/A'}")
    if usage and "prompt_tokens_details" in usage:
        print(f"  Cached tokens: {usage['prompt_tokens_details']['cached_tokens']}")
    
    assert assembler.text, "Should have assembled text"
    assert usage is not None, "Should have extracted usage"
    assert usage["total_tokens"] == 2650, "Should have correct total tokens"
    assert usage["prompt_tokens_details"]["cached_tokens"] == 14570, "Should have cache read tokens"
    
    print("\n✅ Stream simulation passed!")


def main():
    """Run all tests."""
    try:
        # Test 1: Usage extraction
        test_cursor_agent_usage_extraction()
        
        # Test 2: Stream simulation
        asyncio.run(test_cursor_agent_stream_simulation())
        
        print("\n" + "=" * 80)
        print("🎉 ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\nCursor-agent token usage extraction is working correctly.")
        print("Token usage will now be properly reported in both streaming and non-streaming modes.")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
