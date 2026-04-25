# 🏥 CodeVital — The Complete Health Check for Any Codebase

**One command. Full diagnosis. Every project.**

Point CodeVital at any folder and get an instant diagnostic report covering structure, quality, security, dependencies, and an overall health grade (A+ to F) — with actionable recommendations to improve.

```bash
python codevital.py /path/to/your/project
```

## Why this exists

Every developer has asked: *"Is this codebase in good shape?"*

There are linters for code style. Scanners for vulnerabilities. Analyzers for dependencies. But **nobody has built a single tool that gives you the full picture in one shot** — like a doctor's checkup for your code.

CodeVital is that checkup. It scans your project and tells you:

| What it checks | What you learn |
|---|---|
| 📁 **Structure** | README, LICENSE, .gitignore, .env.example, CHANGELOG — is it set up properly? |
| ✨ **Quality** | Tests, CI/CD, linters, formatters, type checking — is it maintainable? |
| 🛡️ **Security** | Hardcoded secrets, exposed .env files, debug mode, missing gitignore rules |
| 📦 **Dependencies** | Lockfiles, pinned versions, declared vs loose dependencies |
| 💻 **Languages** | Auto-detected with line counts and percentage breakdown |
| 🧩 **Frameworks** | Detects React, Next.js, Django, Flask, FastAPI, Express, Vue, and 30+ more |
| 🗑️ **Dead files** | Temp files, logs, empty source files, OS junk committed to the repo |
| 💡 **Recommendations** | Prioritized list of what to fix first, ranked by impact |

All of this produces a single **health grade (A+ to F)** with a 0-100 score.

## Demo

```
🏥 CODEVITAL  —  Health Report

Project: my-web-app
Overall Health: B (72/100)

📊 SCORE BREAKDOWN

  📁 Structure      █████████████████████████░░░░░░░░ 75/100
  ✨ Quality        ████████████████████░░░░░░░░░░░░░ 60/100
  🛡️ Security       █████████████████████████████████ 100/100
  📦 Dependencies   ██████████████████████████████░░░ 90/100

✅ QUALITY CHECKLIST

  ✅ README          ✅ LICENSE         ✅ .gitignore
  ✅ CI/CD Pipeline  ✅ Tests           ✅ Linter config
  ❌ Formatter       ❌ Type checking   ✅ Docker

💡 TOP RECOMMENDATIONS

  🟡 Add a formatter config (e.g., Prettier, Black)
  🟡 Enable type checking (e.g., TypeScript, mypy)
```

Add `--html report.html` for a gorgeous dark-themed visual report you can share with your team.

## Install

```bash
git clone https://github.com/YOUR_USERNAME/codevital.git
cd codevital
pip install -r requirements.txt
```

Only dependency is `rich` for terminal output. Everything else is Python stdlib.

## Usage

Scan the current directory:

```bash
python codevital.py
```

Scan any project:

```bash
python codevital.py /path/to/project
```

Generate an HTML report:

```bash
python codevital.py /path/to/project --html report.html
```

Export as JSON (for CI/CD integration):

```bash
python codevital.py /path/to/project --json results.json
```

## What it detects

### Languages (40+)
Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, Ruby, PHP, Swift, C#, C++, C, Vue, Svelte, Dart, Elixir, Zig, and more.

### Frameworks (30+)
React, Next.js, Nuxt, Vue, Svelte, Angular, Express, Fastify, NestJS, Django, Flask, FastAPI, Streamlit, Gradio, Rails, Spring Boot, Laravel, and more.

### Security checks
- Hardcoded API keys, passwords, and secrets in source code
- AWS access keys and secret keys
- GitHub tokens and OpenAI/Stripe keys
- Exposed `.env` files
- Missing `.env` in `.gitignore`
- `DEBUG = True` in production code
- Technical debt markers (TODO/FIXME/HACK count)

### Quality signals
- README, LICENSE, .gitignore presence
- CI/CD configuration (GitHub Actions, GitLab CI, Jenkins)
- Test files and test-to-code ratio
- Linter configuration (ESLint, Ruff, Flake8, Pylint, RuboCop, etc.)
- Formatter configuration (Prettier, Black, etc.)
- Type checking (TypeScript, mypy, pyright)
- Docker support
- `.env.example` for contributor onboarding
- CONTRIBUTING and CHANGELOG files
- EditorConfig

## Scoring System

Each dimension is scored 0-100:

| Dimension | Weight | What earns points |
|---|---|---|
| **Structure** | 25% | README, LICENSE, .gitignore, Docker, clean file tree |
| **Quality** | 30% | Tests, CI/CD, linting, formatting, type checking |
| **Security** | 30% | No secrets, proper .gitignore, no debug mode |
| **Dependencies** | 15% | Lockfile present, versions pinned, deps declared |

Overall = weighted average → letter grade:

| Score | Grade |
|---|---|
| 90+ | A+ |
| 80-89 | A |
| 70-79 | B |
| 60-69 | C |
| 50-59 | D |
| <50 | F |

## Use Cases

- **Before open-sourcing**: Check your project's readiness for public eyes
- **Code reviews**: Quick health check during PR reviews
- **Onboarding**: Assess a new codebase you've just joined
- **CI/CD gates**: Use `--json` output to fail builds below a threshold
- **Team standards**: Establish a minimum health grade for all repos
- **Portfolio polish**: Make sure your GitHub projects look professional before job hunting
- **Auditing**: Scan third-party code for security red flags before integrating

## Ideas for contributions

- Dependency vulnerability checking (cross-reference with CVE databases)
- Outdated dependency detection (npm outdated / pip-audit integration)
- Git history analysis (combine with git-gossip for the ultimate report)
- Config file validation (is your ESLint config actually valid?)
- Code complexity metrics (cyclomatic complexity, function length)
- Dockerfile best practices audit
- GitHub Action to run CodeVital on every PR
- Badge generation (like shields.io but for your health grade)
- Watch mode — re-scan on file changes
- Compare two projects side-by-side

## FAQ

**Does it modify my files?**
No. CodeVital is read-only. It never writes, deletes, or changes anything in your project.

**Does it send data anywhere?**
No. Everything runs locally. No network requests, no telemetry, no cloud.

**What about monorepos?**
Point it at any subdirectory. It scans from the given root downward.

**Can I use it in CI/CD?**
Yes. Use `--json` to get machine-readable output, then check the `overall` score in your pipeline script.

## License

MIT

---

*Because every codebase deserves a checkup.* 🏥
