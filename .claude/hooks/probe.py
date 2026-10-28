"""Hook probe: logs every Bash call and proves a hook can block or ask.

Try inside a Claude Code session opened in this folder:
  echo SPOOK_TEST_BLOCK   -> denied, reason shown to the agent
  echo SPOOK_TEST_ASK     -> user is asked
  anything else           -> untouched
"""
import json, os, sys, time

data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
cmd = data.get("tool_input", {}).get("command", "")

os.makedirs(".spook", exist_ok=True)
with open(".spook/probe.log", "a", encoding="utf-8") as f:
    f.write(f"{time.strftime('%H:%M:%S')} {data.get('tool_name')} {cmd!r}\n")

decision = reason = None
if "SPOOK_TEST_BLOCK" in cmd:
    decision, reason = "deny", "Spook probe: this command was blocked on purpose."
elif "SPOOK_TEST_ASK" in cmd:
    decision, reason = "ask", "Spook probe: please confirm this command."

if decision:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason}}))
