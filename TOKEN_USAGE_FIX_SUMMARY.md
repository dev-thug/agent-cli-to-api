# Cursor-Agent Token Usage Fix - Complete Summary

## Problem

cursor-agent was correctly called with `--output-format stream-json` and was returning token usage data, but agent-cli-to-api was **not extracting or reporting** this data in API responses.

### Root Cause

The `stream_json_cli_stdin.py` file had usage extraction functions for:
- ✅ Claude: `extract_usage_from_claude_result()` 
- ✅ Gemini: `extract_usage_from_gemini_result()`
- ❌ **cursor-agent: MISSING!**

And in `server.py`:
- Claude extraction was called in non-streaming mode (line ~1761)
- cursor-agent extraction was **never called** in either mode

## Solution

### 1. Added `extract_usage_from_cursor_agent_result()` function

Location: `codex_gateway/stream_json_cli_stdin.py`

```python
def extract_usage_from_cursor_agent_result(evt: dict) -> dict[str, int] | None:
    """
    Extract token usage from cursor-agent result events.
    
    cursor-agent returns usage in camelCase format:
    {
        "type": "result",
        "result": "...",
        "usage": {
            "inputTokens": 123,
            "outputTokens": 456,
            "cacheReadTokens": 789,
            "cacheWriteTokens": 0
        }
    }
    """
    if evt.get("type") != "result":
        return None
    usage = evt.get("usage")
    if not isinstance(usage, dict):
        return None
    
    in_tokens = int(usage.get("inputTokens") or 0)
    out_tokens = int(usage.get("outputTokens") or 0)
    cache_read = int(usage.get("cacheReadTokens") or 0)
    cache_write = int(usage.get("cacheWriteTokens") or 0)
    
    result = {
        "prompt_tokens": in_tokens,
        "completion_tokens": out_tokens,
        "total_tokens": in_tokens + out_tokens,
    }
    
    # Include cache details if present (cursor-specific fields)
    if cache_read > 0 or cache_write > 0:
        result["prompt_tokens_details"] = {
            "cached_tokens": cache_read,
        }
        if cache_write > 0:
            result["cache_creation_input_tokens"] = cache_write
    
    return result
```

### 2. Updated `server.py` imports

```python
from .stream_json_cli_stdin import (
    TextAssembler,
    extract_claude_delta,
    extract_cursor_agent_delta,
    extract_gemini_delta,
    extract_usage_from_claude_result,
+   extract_usage_from_cursor_agent_result,  # ← Added
    extract_usage_from_gemini_result,
    iter_stream_json_events,
)
```

### 3. Added usage extraction in non-streaming mode

Location: `server.py`, line ~1710

```python
async for evt in iter_stream_json_events(...):
    extract_cursor_agent_delta(evt, assembler)
+   maybe_usage = extract_usage_from_cursor_agent_result(evt)  # ← Added
+   if maybe_usage:                                             # ← Added
+       usage = maybe_usage                                     # ← Added
    if evt.get("type") == "result" and isinstance(evt.get("result"), str):
        fallback_text = evt["result"]
```

### 4. Added usage extraction in streaming mode

Location: `server.py`, line ~2209

```python
elif provider == "cursor-agent":
    # ... init logging ...
    delta = _maybe_strip_answer_tags(extract_cursor_agent_delta(evt, assembler))
+   maybe_usage = extract_usage_from_cursor_agent_result(evt)  # ← Added
+   if maybe_usage:                                             # ← Added
+       stream_usage = maybe_usage                              # ← Added
```

## Field Mapping

cursor-agent uses **camelCase**, but OpenAI API uses **snake_case**:

| cursor-agent field | OpenAI API field | Notes |
|-------------------|------------------|-------|
| `inputTokens` | `prompt_tokens` | Input tokens |
| `outputTokens` | `completion_tokens` | Output tokens |
| `cacheReadTokens` | `prompt_tokens_details.cached_tokens` | Cache hits |
| `cacheWriteTokens` | `cache_creation_input_tokens` | Cache writes |

## Example Output

### Before Fix
```json
{
  "id": "chatcmpl-xxx",
  "model": "cursor-agent",
  "choices": [...],
  "usage": null  // ❌ No usage data!
}
```

### After Fix
```json
{
  "id": "chatcmpl-xxx",
  "model": "cursor-agent",
  "choices": [...],
  "usage": {
    "prompt_tokens": 1250,
    "completion_tokens": 89,
    "total_tokens": 1339,
    "prompt_tokens_details": {
      "cached_tokens": 8500  // ✅ Cache hits tracked!
    }
  }
}
```

## Test Results

### Unit Tests
```bash
$ python test_cursor_agent_usage.py

✅ TEST 1: Basic usage (no cache) - PASSED
✅ TEST 2: Usage with cache read - PASSED
✅ TEST 3: Usage with cache write - PASSED
✅ TEST 4: Usage with both cache operations - PASSED
✅ TEST 5: Non-result events - PASSED
✅ TEST 6: Missing usage field - PASSED

🎉 ALL TESTS PASSED!
```

### API Integration Tests
```bash
$ python test_cursor_agent_api_integration.py

✅ Non-streaming mode returns token usage
✅ Streaming mode works correctly
✅ Cache tokens are properly tracked

🎉 ALL INTEGRATION TESTS PASSED!
```

## Files Changed

1. **`codex_gateway/stream_json_cli_stdin.py`** (PR repo + local)
   - Added `extract_usage_from_cursor_agent_result()` function (~60 lines)

2. **`codex_gateway/server.py`** (local only, instructions provided for upstream)
   - Import the new function (1 line)
   - Extract usage in non-streaming mode (3 lines)
   - Extract usage in streaming mode (3 lines)

3. **Tests** (PR repo)
   - `test_cursor_agent_usage.py` - Unit tests
   - `test_cursor_agent_api_integration.py` - API integration tests

4. **Documentation** (PR repo)
   - `README.md` - Updated with token usage fix info
   - `PR.md` - Updated PR description

## Verification Steps

1. **Unit tests:**
   ```bash
   cd agent-cli-to-api-local
   python test_cursor_agent_usage.py
   ```

2. **API integration test:**
   ```bash
   python test_cursor_agent_api_integration.py
   ```

3. **Manual verification with real cursor-agent:**
   ```bash
   # Start server
   CURSOR_AGENT_BIN=/path/to/cursor-agent uvicorn codex_gateway.server:app
   
   # Make request
   curl -X POST http://localhost:8000/v1/chat/completions \
     -H "Content-Type: application/json" \
     -d '{
       "model": "cursor-agent",
       "messages": [{"role": "user", "content": "Hello"}],
       "stream": false
     }'
   
   # Check response has "usage" field with:
   # - prompt_tokens
   # - completion_tokens
   # - total_tokens
   # - prompt_tokens_details.cached_tokens (if cache hit)
   ```

## Impact

### Before
- ❌ No token usage reported
- ❌ No way to track cache efficiency
- ❌ No billing/cost visibility

### After
- ✅ Full token usage reporting
- ✅ Cache hit/miss tracking
- ✅ Complete cost visibility
- ✅ Matches OpenAI API format

## Benefits

1. **Cost tracking**: Users can now see exactly how many tokens each request uses
2. **Cache monitoring**: Track cache hits (`cacheReadTokens`) to see caching efficiency
3. **Performance**: Identify expensive requests by token count
4. **Billing**: Accurate token counts for cost allocation
5. **Debugging**: Usage anomalies can indicate prompt issues

## Status

✅ **Complete and tested**

- Unit tests pass
- Integration tests pass
- Code is production-ready
- Documentation updated
- Pushed to GitHub: https://github.com/Teglgaard/agent-cli-to-api-stdin-fix
- Ready for upstream PR to https://github.com/dev-thug/agent-cli-to-api
