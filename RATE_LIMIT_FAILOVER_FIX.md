# Rate Limit Failover Fix for OpenClaw Compatibility

## Problem

When Claude Code (or other providers) hit rate limits, the gateway was returning:
- **HTTP Status:** `500` (Internal Server Error)
- **Error Type:** `codex_gateway_error`

This prevented OpenClaw from recognizing the error as a rate limit, **blocking automatic failover** to the next model.

## Solution

The gateway now automatically detects rate limit errors in error messages and returns:
- **HTTP Status:** `429` (Too Many Requests)
- **Error Type:** `rate_limit_error`
- **Error Code:** `rate_limit_exceeded`

### Detection Logic

The fix detects rate limit errors by checking error messages for these phrases:
- `"hit your limit"`
- `"rate limit"`
- `"too many requests"`
- `"quota exceeded"`
- `"usage limit"`

### Code Change

**Location:** `codex_gateway/server.py` - `_openai_error()` function

```python
def _openai_error(message: str, *, status_code: int = 500) -> JSONResponse:
    """
    Return an OpenAI-compatible error response.
    
    Automatically detects rate limit errors and returns HTTP 429 with
    rate_limit_error type for OpenClaw failover compatibility.
    """
    # Detect rate limit errors for OpenClaw failover
    error_type = "codex_gateway_error"
    error_code = None
    
    message_lower = message.lower()
    if any(phrase in message_lower for phrase in [
        "hit your limit",
        "rate limit",
        "too many requests",
        "quota exceeded",
        "usage limit"
    ]):
        error_type = "rate_limit_error"
        error_code = "rate_limit_exceeded"
        status_code = 429  # Override to 429 for rate limits
    
    payload = ErrorResponse(
        error={
            "message": message,
            "type": error_type,
            "param": None,
            "code": error_code,
        }
    ).model_dump()
    return JSONResponse(status_code=status_code, content=payload)
```

## Before vs After

### Before Fix

**Claude Code rate limit response:**
```json
{
  "error": {
    "message": "You've hit your limit · resets 6pm (Europe/Copenhagen)",
    "type": "codex_gateway_error",  // ❌ Wrong type
    "param": null,
    "code": null
  }
}
```
**HTTP Status:** `500` ❌

**Result:** OpenClaw shows error, no failover

### After Fix

**Claude Code rate limit response:**
```json
{
  "error": {
    "message": "You've hit your limit · resets 6pm (Europe/Copenhagen)",
    "type": "rate_limit_error",  // ✅ Correct type
    "param": null,
    "code": "rate_limit_exceeded"  // ✅ Proper code
  }
}
```
**HTTP Status:** `429` ✅

**Result:** OpenClaw recognizes rate limit, triggers failover to next model

## OpenClaw Failover Behavior

According to [OpenClaw's Model Failover documentation](https://docs.openclaw.ai/concepts/model-failover):

> "If all profiles for a provider fail, OpenClaw moves to the next model in `agents.defaults.model.fallbacks`. **This applies to auth failures, rate limits, and timeouts**"

With this fix, OpenClaw will now correctly:

1. Detect the `429` status and `rate_limit_error` type
2. Recognize it as a rate limit (not a generic error)
3. Move to the next model in your fallbacks list
4. Continue working seamlessly

### Example OpenClaw Config

```yaml
agents:
  defaults:
    model:
      value: "claude:opus"
      fallbacks:
        - "cursor:auto"      # ← Falls back here on Claude rate limit
        - "codex:gpt-5.2"    # ← Then here if Cursor fails
```

## Test Results

```bash
$ python test_rate_limit_failover.py

✅ Claude Code rate limit message - PASSED
✅ Generic rate limit message - PASSED
✅ Too many requests message - PASSED
✅ Quota exceeded message - PASSED
✅ Usage limit message - PASSED
✅ Non-rate-limit errors still return 500 - PASSED
✅ OpenAI API format compliance - PASSED

🎉 ALL TESTS PASSED!
```

## Testing Manually

### Simulate a Rate Limit Error

```bash
# Start the gateway
cd agent-cli-to-api-fork
uv run agent-cli-to-api claude --host 127.0.0.1 --port 8000

# Trigger a rate limit (use Claude Code until you hit the limit)
# Or test with a mock error:
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer devtoken" \
  -d '{
    "model": "claude",
    "messages": [{"role": "user", "content": "test"}]
  }'
```

When you hit the rate limit, the response will be:
```json
{
  "error": {
    "message": "You've hit your limit · resets 6pm (Europe/Copenhagen)",
    "type": "rate_limit_error",
    "param": null,
    "code": "rate_limit_exceeded"
  }
}
```
**HTTP Status:** `429`

### Test with OpenClaw

1. Configure OpenClaw with multiple model fallbacks
2. Use Claude Code as the primary model
3. Trigger the rate limit
4. **Expected:** OpenClaw automatically falls back to the next model
5. **Verify:** Check OpenClaw logs for failover messages

## Impact

| Scenario | Before Fix | After Fix |
|----------|-----------|-----------|
| **Claude rate limit** | ❌ Shows error, no failover | ✅ Auto-fails over to next model |
| **Cursor rate limit** | ❌ Shows error, no failover | ✅ Auto-fails over to next model |
| **Any rate limit** | ❌ Blocks workflow | ✅ Seamless continuation |
| **Other errors** | ✅ Proper error (500) | ✅ Proper error (500) |

## Why This Matters

### Without This Fix
```
User → Claude Code → Rate Limit (429)
  ↓
Gateway → HTTP 500 + codex_gateway_error
  ↓
OpenClaw → Shows error, stops working ❌
  ↓
User → Must manually switch models
```

### With This Fix
```
User → Claude Code → Rate Limit (429)
  ↓
Gateway → HTTP 429 + rate_limit_error
  ↓
OpenClaw → Recognizes rate limit, triggers failover ✅
  ↓
OpenClaw → Automatically uses Cursor (or next fallback)
  ↓
User → Continues working seamlessly 🎉
```

## Status

✅ **Implemented and tested** in:
- `agent-cli-to-api-fork` (your main fork)
- `agent-cli-to-api-local` (testing environment)

Ready for production use with OpenClaw!

## Related Documentation

- [OpenClaw Model Failover](https://docs.openclaw.ai/concepts/model-failover)
- [OpenAI Error Codes](https://platform.openai.com/docs/guides/error-codes)
- OpenAI 429 Rate Limit Response Format
