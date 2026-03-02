<p align="center">
  <img src="images/dippy.gif" width="200">
</p>

<h1 align="center">🐤 Dippy</h1>
<p align="center"><em>Because <code>ls</code> shouldn't need approval</em></p>

This is a fork of [ldayton/Dippy](https://github.com/ldayton/Dippy). See [Diff with origin Dippy](#diff-with-origin-dippy) for what changed.

---

> **Stop the permission fatigue.** Claude Code asks for approval on every `ls`, `git status`, and `cat` - destroying your flow state. You check Slack, come back, and your assistant's just sitting there waiting.

Dippy is a shell command hook that auto-approves safe commands while still prompting for anything destructive. When it blocks, your custom deny messages can steer Claude back on track—no wasted turns. Get up to **40% faster development** without disabling permissions entirely.

Built on [Parable](https://github.com/ldayton/Parable), our own hand-written bash parser—no external dependencies, just pure Python. 14,000+ tests between the two.

***Example: rejecting unsafe operation in a chain***

![Screenshot](images/terraform-apply.png)

***Example: rejecting a command with advice, so Claude can keep going***

![Deny with message](images/deny-with-message.png)

## ✅ What gets approved

- **Complex pipelines**: `ps aux | grep python | awk '{print $2}' | head -10`
- **Chained reads**: `git status && git log --oneline -5 && git diff --stat`
- **Cloud inspection**: `aws ec2 describe-instances --filters "Name=tag:Environment,Values=prod"`
- **Container debugging**: `docker logs --tail 100 api-server 2>&1 | grep ERROR`
- **Safe redirects**: `grep -r "TODO" src/ 2>/dev/null`, `ls &>/dev/null`
- **Command substitution**: `ls $(pwd)`, `git diff foo-$(date).txt`

![Safe command substitution](images/safe-cmd-sub.png)

## 🚫 What gets blocked

- **Subshell injection**: `git $(echo rm) foo.txt`, `echo $(rm -rf /)`
- **Subtle file writes**: `curl https://example.com > script.sh`, `tee output.log`
- **Hidden mutations**: `git stash drop`, `npm unpublish`, `brew unlink`
- **Cloud danger**: `aws s3 rm s3://bucket --recursive`, `kubectl delete pod`
- **Destructive chains**: `rm -rf node_modules && npm install` (blocks the whole thing)

![Redirect blocked](images/redirect.png)

---

## Installation

### Homebrew (recommended)

```bash
brew tap ldayton/dippy
brew install dippy
```

### Manual

```bash
git clone https://github.com/ldayton/Dippy.git
```

### Configure

Add to `~/.claude/settings.json` (or use `/hooks` interactively):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "dippy" }]
      }
    ]
  }
}
```

If you installed manually, use the full path instead: `/path/to/Dippy/bin/dippy-hook`

---

## Configuration

Dippy is highly customizable. Beyond simple allow/deny rules, you can attach messages that steer the AI back on track when it goes astray—no wasted turns.

```
deny python "Use uv run python, which runs in project environment"
deny rm -rf "Use trash instead"
deny-redirect **/.env* "Never write secrets, ask me to do it"
```

Dippy reads config from `~/.dippy/config` (global) and `.dippy` in your project root.

**Full documentation:** [Dippy Wiki](https://github.com/ldayton/Dippy/wiki)

---

## Extensions

See the [wiki](https://github.com/ldayton/Dippy/wiki) for additional capabilities. Fork-specific extensions are listed in [Diff with origin Dippy](#diff-with-origin-dippy).

---

## Diff with origin Dippy

This fork adds the following changes on top of [ldayton/Dippy](https://github.com/ldayton/Dippy):

### Script Unfolding

When Claude runs `bash script.sh`, Dippy reads and analyzes every command inside the script instead of blindly approving or blocking. Safe scripts are auto-approved; unsafe ones report exactly which line failed. Supports `bash`/`sh`/`zsh script.sh`, `./script.sh`, and `source script.sh` patterns with depth-limited recursion.

**Performance** (tested on MacBook M1 Pro) — analysis scales linearly (~0.16 ms/line):

| Script size | Time |
|-------------|------|
| 100 lines | ~16 ms |
| 500 lines | ~80 ms |
| 1,000 lines | ~160 ms |
| 2,000 lines | ~320 ms |
| 5,000 lines | ~800 ms |
| 10,000 lines | ~1,600 ms |

---

## Uninstall

Remove the hook entry from `~/.claude/settings.json`, then:

```bash
brew uninstall dippy  # if installed via Homebrew
```
