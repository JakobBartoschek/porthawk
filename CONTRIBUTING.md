# Contributing to PortHawk

Thanks for taking the time to contribute. This project is a security tool — contributions
that expand scan capabilities, improve output quality, or add integrations are most welcome.

---

## Quick Setup

```bash
# 1. Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/porthawk
cd porthawk

# 2. Create a virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Install runtime + dev dependencies
pip install -r requirements-dev.txt

# 4. Verify tests pass before touching anything
pytest tests/ -v
```

---

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| New feature | `feature/xxx` | `feature/nvd-cve-lookup` |
| Bug fix | `fix/xxx` | `fix/udp-timeout-windows` |
| Docs | `docs/xxx` | `docs/add-usage-examples` |
| Refactor | `refactor/xxx` | `refactor/reporter-split` |

Keep branches short-lived. One concern per branch.

---

## Before You Submit a PR

```bash
# Run the full test suite
pytest tests/ --cov=porthawk --cov-report=term-missing

# Check coverage didn't drop
# Target: >90% on porthawk/ modules

# If you have black and ruff installed:
black porthawk/ tests/
ruff check porthawk/
```

New code needs tests. If you add a function, add a test for it.
If you change network behavior, mock it — no real connections in tests.

---

## Code Style

- **Formatter:** black (line length 100)
- **Linter:** ruff (E, F, I, UP, B rules)
- **Type hints** on all public functions — Python 3.10+ union syntax (`X | Y`)
- **Docstrings** in Google style on public functions
- **Comments** should explain *why*, not *what* — if it's obvious from the code, skip it
- **Max 30 lines per function** — if it's longer, think about splitting it
- No bare `except:` — always catch a specific exception type

---

## Writing a Good Pull Request

**Title:** Short and specific. `Add CVE lookup via NVD API` not `Add feature`.

**Body should include:**
1. What changed and why
2. How to test it manually
3. Any limitations or known issues

**What we'll check in review:**
- Does it have tests?
- Does coverage stay above 90%?
- Does it introduce any real network calls in tests?
- Is the code readable by someone unfamiliar with the codebase?

---

## Code of Conduct

1. Be direct and constructive in reviews — attack the code, not the person.
2. This tool is for authorized security testing. Don't contribute features designed to evade detection or attack infrastructure without permission.
3. Keep discussions on-topic. GitHub issues are for bugs and features, not general security questions.
4. If you're new to contributing, start with a small fix or doc improvement.
5. We review PRs within a week. If you haven't heard back, ping in the issue thread.
