# ARCHITECTURE.md — agent-guard

Pattern-based prompt injection and command injection detection for AI agents. Read this before making changes.

## Overview

agent-guard is a defense-in-depth scanning tool that screens text for known malicious patterns. It catches common attacks including command injection, prompt injection, social engineering, encoding obfuscation, container escape, and CI/CD pipeline injection. Designed as an OpenClaw skill invoked via CLI.

**This is a speed bump, not a wall.** Sophisticated adversaries can bypass regex-based detection. Always pair with architectural security (sandboxing, least-privilege, human-in-the-loop).

- **Version:** 1.0.1
- **Author:** vflame6
- **License:** MIT
- **Runtime:** Python 3 (stdlib only, no external deps)
- **Repo:** https://github.com/erra9x/agent-guard

## Project Structure

```
agent-guard/
├── scripts/
│   └── agent_guard.py      # Main scanning engine + CLI (≈700 lines)
├── tests/
│   └── test_agent_guard.py  # Comprehensive test suite (≈750 lines)
├── SKILL.md                 # OpenClaw skill definition + usage protocol
├── _meta.json               # Skill metadata (version, tags, compatibility)
├── ARCHITECTURE.md          # This file
├── README.md                # User-facing readme
└── LICENSE                  # MIT license
```

## Pattern Categories (156 total)

| Category | Count | What it detects |
|----------|-------|-----------------|
| **injection** | 44 | Prompt injection (direct, indirect, multi-language), role overrides, hidden HTML/XML, RAG extraction, tool manipulation |
| **execution** | 32 | Pipe-to-shell (`curl \| bash`), destructive commands (`rm -rf`), code execution (`eval`, `exec`, `os.system`), package installs from URLs, Windows commands (`powershell -enc`, `cmd /c`), scripting (`python -c`, `node -e`) |
| **social** | 23 | Urgency manipulation, trust exploitation, authority impersonation, fake system errors, maintenance mode simulation, developer/researcher impersonation, translation injection |
| **container** | 13 | Docker privileged mode, root filesystem mounts, dangerous capabilities (`CAP_ALL`, `SYS_ADMIN`), host namespace sharing, Dockerfile pipe-to-shell, docker.sock mounts, security-opt bypasses |
| **network** | 13 | Reverse shells (`nc -l`, `/dev/tcp/`), suspicious domains (`.onion`, pastebin), data exfiltration (HTTP POST, DNS to collaborator domains), raw GitHub URLs |
| **cicd** | 10 | GitHub Actions expression injection, Jenkins Groovy injection, GitLab CI remote includes, Terraform remote modules, Ansible shell pipe-to-bash, Codecov-style supply chain attacks |
| **encoding** | 9 | Base64 decode commands, `chr()` concatenation, command substitution, hex strings, Unicode escapes, `atob()`, `Buffer.from()` |
| **filesystem** | 8 | Writes to dotfiles (`.bashrc`, `.ssh/authorized_keys`), system file writes (`/etc/passwd`, `/etc/sudoers`), crontab manipulation, systemctl commands |
| **rendering** | 4 | Right-to-left override characters, invisible Unicode obfuscation, IDN homograph URLs (`xn--`) |

### Multi-language injection coverage

Injection patterns include equivalents of "ignore previous instructions" in: English, Russian, Chinese (Simplified), Spanish, German, French, Japanese, and Korean.

## How Scanning Works

The core pipeline: **normalize → regex match → score → classify**.

### 1. Normalize

Two normalization passes run on every input:

- **Full normalization** (`_normalize_text`): NFKD decompose → strip combining marks → NFC recompose → strip zero-width/bidi chars → collapse whitespace → replace homoglyphs (Cyrillic/Greek → Latin). Used for English-centric patterns.
- **Light normalization** (`_normalize_text_light`): Only strips invisible characters and collapses whitespace. Preserves non-Latin scripts (Russian й, Chinese characters). Used for multi-language injection patterns.

Before normalization, suspicious Unicode characters (zero-width, RTO, bidi) are counted — these generate their own match if found.

### 2. Regex Match

All 156 compiled patterns run against the normalized text. Each pattern has a severity (`low`, `medium`, `high`, `critical`) and belongs to a category.

- **Execution patterns** use `findall` (captures all command instances)
- **All other patterns** use `search` (first match is enough)
- **ReDoS protection**: Each regex has a signal-based timeout (`SIGALRM`, 100ms default) to prevent catastrophic backtracking. Falls back to no-timeout on Windows or non-main threads.

### 3. Base64 Decode Layer

After regex matching, base64 blobs (≥20 chars) in the input are decoded. If decoded content is >70% printable, it's re-scanned through all patterns. Matches from decoded content are tagged `[base64-decoded]`.

### 4. Score

Risk score is calculated from matches using:

```
score = Σ (category_weight × severity_weight × diminishing_factor) × context_multiplier
```

- **Severity weights:** low=0.5, medium=1.5, high=3.0, critical=5.0
- **Category weights:** injection=2.0, execution=1.5, network=1.5, container=1.5, social=1.2, filesystem=1.2, cicd=1.2, rendering=1.0, encoding=0.8
- **Diminishing returns:** `1/√(count)` per category — prevents one category from dominating
- **Context multipliers:** github_title=1.5×, github_body=1.2×, developer=0.5×, general=1.0×

### 5. Classify

Score maps to threat level:

| Score | Threat Level |
|-------|-------------|
| < 2.0 | `safe` |
| 2.0–4.99 | `suspicious` |
| 5.0–7.99 | `dangerous` |
| ≥ 8.0 | `critical` |

### Confidence

Separate from risk score. Based on highest severity match (0.3–0.9) and total match count (up to 1.0). Indicates how sure the engine is that the detected patterns are real threats.

## False Positive Strategy

### LRU Cache

Thread-safe `OrderedDict`-based LRU cache (default 10,000 entries). Cache key is SHA-256 of `version:context:normalized_full:normalized_light`. Cached results skip all pattern matching — only `analysis_time_ms` is recalculated.

### Context-Aware Scoring

The `--context` flag adjusts sensitivity:

- **`developer`** (0.5× multiplier): For trusted developer conversations where `npm install`, `pip install`, `git clone` are expected. Prevents common dev commands from triggering.
- **`github_title`** (1.5× multiplier): Higher sensitivity for GitHub issue titles (Clinejection attack vector).
- **`github_body`** (1.2× multiplier): Slightly elevated for issue bodies.
- **`general`** (1.0×): Default for most content.

### Sanitization

When threat level is non-safe, matched patterns are replaced with category-specific placeholders (`[BLOCKED_COMMAND]`, `[BLOCKED_INJECTION]`, etc.) in the sanitized output.

## GitHub Issue Analysis (Clinejection)

`analyze_github_issue()` runs title and body through separate analyses (with appropriate context multipliers), then combines:

- **clinejection_risk** = `true` if: title score > 2.0, body score > 4.0, or any execution commands found
- **should_block** = `true` if overall threat is `dangerous` or `critical`

## Test Structure

181 tests in `tests/test_agent_guard.py` using `unittest`. Run with:

```bash
cd /path/to/agent-guard
python3 -m pytest tests/ -v
# or
python3 tests/test_agent_guard.py
```

No external dependencies needed — stdlib only.

### Test Classes

| Class | Tests | What it covers |
|-------|-------|----------------|
| `TestSafeContent` | 12 | True negatives: legitimate content that should NOT trigger |
| `TestCommandInjection` | 9 | Pipe-to-shell, destructive commands, code execution |
| `TestPromptInjection` | 14 | Direct/indirect injection, role overrides, hidden HTML |
| `TestMultiLanguageInjection` | 5 | Russian, Chinese, Spanish, German, French |
| `TestSocialEngineering` | 5 | Urgency, trust exploitation, authority impersonation |
| `TestFilesystemManipulation` | 5 | SSH keys, dotfile writes, system file access |
| `TestNetworkOperations` | 5 | Reverse shells, data exfiltration, DNS exfil |
| `TestEncodingObfuscation` | 5 | Base64, chr(), RTO, atob, Buffer.from |
| `TestBase64DecodeLayer` | 2 | Base64 blob detection and re-scanning |
| `TestClinejection` | 3 | GitHub issue attack detection |
| `TestUnicodeBypasses` | 4 | Homoglyphs, zero-width, combining chars |
| `TestEdgeCases` | 7 | Empty input, oversized input, binary, Unicode-heavy |
| `TestJSONOutput` | 6 | Schema consistency and serialization |
| `TestCLIOutput` | 7 | CLI subcommands produce correct output |
| `TestContainerInjection` | 21 | Docker/compose injection + false positive checks |
| `TestTranslationInjection` | 4 | Two-step translation attacks |
| `TestSystemErrorSimulation` | 7 | Fake error/maintenance mode attacks |
| `TestRAGDataExtraction` | 6 | Scope expansion and data extraction attacks |
| `TestCICDInjection` | 18 | CI/CD pipeline injection + false positive checks |
| `TestPerformance` | 3 | Speed benchmarks (<10ms single, <1ms cached) |
| `TestRateLimiting` | 3 | Rate limit enforcement and source isolation |

## How to Add New Patterns

1. **Choose the category** from the existing ones in `_build_patterns()`, or create a new one.

2. **Add the regex tuple** to the appropriate list:
   ```python
   (r'your_regex_here', "severity"),  # low|medium|high|critical
   ```

3. **If creating a new category**, also add:
   - Category weight in `_calculate_risk()` → `category_weights` dict
   - Sanitization placeholder in `_sanitize()` → `replacements` dict
   - Add the category key to the `raw_patterns` dict at the bottom of `_build_patterns()`

4. **Write tests** — add both true positive and true negative (false positive check) test cases.

5. **Run the full suite** to verify no regressions:
   ```bash
   python3 -m pytest tests/ -v
   ```

### Severity Guidelines

- **`low`**: Informational, common in legitimate use (e.g., `/tmp/` paths, `./script`)
- **`medium`**: Worth noting, common in dev but risky from untrusted sources (e.g., `npm install`, `sudo`)
- **`high`**: Likely malicious in untrusted context (e.g., `eval()`, reverse shells, hidden HTML)
- **`critical`**: Almost always malicious (e.g., `curl | bash`, `rm -rf`, `ignore previous instructions`)

## CLI Usage

```bash
# Analyze text
python3 scripts/agent_guard.py analyze "text to scan" --json
python3 scripts/agent_guard.py analyze --stdin --json < file.txt
python3 scripts/agent_guard.py analyze "npm install express" --context developer --json

# Analyze GitHub issue
python3 scripts/agent_guard.py github-issue --title "Issue title" --body "Issue body" --json

# Show pattern statistics
python3 scripts/agent_guard.py report --json

# Version
python3 scripts/agent_guard.py version
```

## Skill Usage (OpenClaw)

When the agent-guard skill is active in OpenClaw, the agent follows an automatic screening protocol:

- **Trusted contexts** (private 1-on-1 with owner): No screening
- **Untrusted contexts** (group chats, external content, GitHub issues, webhooks): Always screen
- **Critical/Dangerous**: Block execution, inform user
- **Suspicious**: Warn user, ask for confirmation
- **Safe**: Proceed normally

See `SKILL.md` for the full protocol including Dockerfile/Docker Compose scanning.

## Key Design Decisions

- **Stdlib only** — no external dependencies, runs anywhere Python 3 is available
- **Immutable results** — `DetectionResult` and `PatternMatch` are frozen dataclasses
- **Two-pass normalization** — full (English) + light (multi-language) to avoid corrupting non-Latin scripts
- **Signal-based regex timeout** — prevents ReDoS on Unix, graceful fallback on Windows
- **Diminishing returns scoring** — prevents one category from inflating the score
- **LRU cache** — thread-safe, avoids re-scanning identical content

## Recent Additions (v1.0.1)

- **Container patterns** (13): Docker privileged mode, dangerous capabilities, host namespace, Dockerfile pipe-to-shell, compose privileged/host-network, docker.sock mounts, security-opt bypasses, docker save/export/cp/exec abuse
- **CI/CD patterns** (10): GitHub Actions expression injection, Jenkins Groovy, GitLab CI remote includes, Terraform remote modules, Ansible shell injection, Codecov-style supply chain, artifact poisoning
- **Activation logic**: Context-aware screening protocol — trusted vs untrusted sources, automatic vs manual scanning
- **Dockerfile scanning protocol**: Dedicated scanning workflow for untrusted Dockerfiles and docker-compose files
- **Translation injection**: Two-step attacks using translate-then-execute patterns
- **System error simulation**: Fake ERROR/ALERT/maintenance mode patterns
- **RAG data extraction**: Scope expansion and confidential data access patterns
- **Developer/researcher impersonation**: Authority-based social engineering patterns
