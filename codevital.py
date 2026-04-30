"""
CodeVital — The Complete Health Check for Any Codebase
Scan any project folder and get a comprehensive diagnostic report:
dependencies, security, structure, quality, and an overall health score.
by adithyakiranhere
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


# ─── Ignore Rules ────────────────────────────────────────────────────
IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", "target", ".next", ".nuxt", "out",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache", ".tox",
    "vendor", "bower_components", ".gradle", ".cargo", "coverage",
    "egg-info", ".eggs", "site-packages",".vim"
}

IGNORE_FILES = {
    ".DS_Store", "Thumbs.db", "desktop.ini",
}


# ─── Language Detection ──────────────────────────────────────────────

LANG_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "React (JSX)", ".tsx": "React (TSX)",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin",
    ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".cs": "C#",
    ".cpp": "C++", ".c": "C", ".h": "C/C++ Header",
    ".html": "HTML", ".css": "CSS", ".scss": "SCSS", ".sass": "Sass",
    ".vue": "Vue", ".svelte": "Svelte",
    ".sql": "SQL", ".sh": "Shell", ".bash": "Bash",
    ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML",
    ".json": "JSON", ".xml": "XML", ".md": "Markdown",
    ".r": "R", ".R": "R", ".dart": "Dart", ".lua": "Lua",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang",
    ".zig": "Zig", ".nim": "Nim", ".ml": "OCaml",
}

FRAMEWORK_SIGNALS = {
    "package.json": {
        "next": "Next.js", "nuxt": "Nuxt", "react": "React",
        "vue": "Vue", "svelte": "Svelte", "angular": "Angular",
        "express": "Express", "fastify": "Fastify", "nest": "NestJS",
        "electron": "Electron", "react-native": "React Native",
        "gatsby": "Gatsby", "remix": "Remix", "astro": "Astro",
    },
    "requirements.txt": {
        "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
        "tornado": "Tornado", "celery": "Celery", "scrapy": "Scrapy",
        "pytest": "pytest", "numpy": "NumPy", "pandas": "pandas",
        "tensorflow": "TensorFlow", "torch": "PyTorch",
        "streamlit": "Streamlit", "gradio": "Gradio",
    },
}


# ─── Data Structures ─────────────────────────────────────────────────

@dataclass
class FileInfo:
    path: Path
    extension: str
    size: int
    lines: int = 0


@dataclass
class DependencyInfo:
    name: str
    version: str = ""
    source: str = ""  # requirements.txt, package.json, etc.
    is_dev: bool = False


@dataclass
class SecurityFinding:
    severity: str  # critical, high, medium, low, info
    category: str
    message: str
    file: str = ""
    line: int = 0


@dataclass
class HealthReport:
    project_name: str
    scan_time: str
    root: Path

    # Structure
    total_files: int = 0
    total_dirs: int = 0
    total_lines: int = 0
    total_size_bytes: int = 0
    languages: dict = field(default_factory=dict)
    frameworks: list = field(default_factory=list)
    file_types: dict = field(default_factory=dict)
    largest_files: list = field(default_factory=list)

    # Dependencies
    dependencies: list = field(default_factory=list)
    has_lockfile: bool = False
    has_pinned_versions: bool = False

    # Quality signals
    has_readme: bool = False
    has_license: bool = False
    has_gitignore: bool = False
    has_ci: bool = False
    has_tests: bool = False
    has_docker: bool = False
    has_env_example: bool = False
    has_contributing: bool = False
    has_changelog: bool = False
    has_editorconfig: bool = False
    has_linter_config: bool = False
    has_formatter_config: bool = False
    has_type_checking: bool = False
    test_file_count: int = 0
    test_ratio: float = 0.0

    # Security
    security_findings: list = field(default_factory=list)

    # Dead files
    potentially_dead: list = field(default_factory=list)

    # Scores
    structure_score: int = 0
    quality_score: int = 0
    security_score: int = 0
    dependency_score: int = 0
    overall_score: int = 0
    overall_grade: str = "F"


# ─── Scanners ─────────────────────────────────────────────────────────

def scan_files(root: Path) -> list[FileInfo]:
    """Walk the project tree and collect file info."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]

        for fname in filenames:
            if fname in IGNORE_FILES:
                continue
            fpath = Path(dirpath) / fname
            try:
                size = fpath.stat().st_size
                ext = fpath.suffix.lower()
                lines = 0
                if ext in LANG_MAP or ext in {".txt", ".md", ".cfg", ".ini", ".env"}:
                    try:
                        lines = sum(1 for _ in fpath.open("r", errors="ignore"))
                    except Exception:
                        pass
                files.append(FileInfo(path=fpath, extension=ext, size=size, lines=lines))
            except (OSError, PermissionError):
                continue
    return files


def detect_languages(files: list[FileInfo]) -> dict[str, dict]:
    """Count files and lines per language."""
    langs = defaultdict(lambda: {"files": 0, "lines": 0})
    for f in files:
        lang = LANG_MAP.get(f.extension)
        if lang:
            langs[lang]["files"] += 1
            langs[lang]["lines"] += f.lines
    return dict(sorted(langs.items(), key=lambda x: x[1]["lines"], reverse=True))


def detect_frameworks(root: Path) -> list[str]:
    """Detect frameworks from manifest files."""
    frameworks = []

    # JavaScript/TypeScript
    pkg_path = root / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text())
            all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for dep_key, framework_name in FRAMEWORK_SIGNALS["package.json"].items():
                if dep_key in all_deps:
                    frameworks.append(framework_name)
        except (json.JSONDecodeError, OSError):
            pass

    # Python
    req_path = root / "requirements.txt"
    if req_path.exists():
        try:
            content = req_path.read_text().lower()
            for dep_key, framework_name in FRAMEWORK_SIGNALS["requirements.txt"].items():
                if dep_key in content:
                    frameworks.append(framework_name)
        except OSError:
            pass

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text().lower()
            for dep_key, framework_name in FRAMEWORK_SIGNALS["requirements.txt"].items():
                if dep_key in content:
                    frameworks.append(framework_name)
        except OSError:
            pass

    # Other framework signals
    if (root / "manage.py").exists():
        if "Django" not in frameworks:
            frameworks.append("Django")
    if (root / "Cargo.toml").exists():
        frameworks.append("Cargo (Rust)")
    if (root / "go.mod").exists():
        frameworks.append("Go Modules")
    if (root / "Gemfile").exists():
        frameworks.append("Bundler (Ruby)")
    if (root / "pom.xml").exists():
        frameworks.append("Maven")
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        frameworks.append("Gradle")
    if (root / "composer.json").exists():
        frameworks.append("Composer (PHP)")

    return list(dict.fromkeys(frameworks))  # deduplicate preserving order


def parse_dependencies(root: Path) -> list[DependencyInfo]:
    """Parse dependency files."""
    deps = []

    # Python
    for req_file in ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]:
        path = root / req_file
        if path.exists():
            is_dev = "dev" in req_file
            try:
                for line in path.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Parse name and version
                    match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+.+)?", line)
                    if match:
                        deps.append(DependencyInfo(
                            name=match.group(1),
                            version=match.group(2) or "unpinned",
                            source=req_file,
                            is_dev=is_dev,
                        ))
            except OSError:
                pass

    # Node.js
    pkg_path = root / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text())
            for name, version in pkg.get("dependencies", {}).items():
                deps.append(DependencyInfo(name=name, version=version, source="package.json"))
            for name, version in pkg.get("devDependencies", {}).items():
                deps.append(DependencyInfo(name=name, version=version, source="package.json", is_dev=True))
        except (json.JSONDecodeError, OSError):
            pass

    return deps


def check_lockfiles(root: Path) -> bool:
    """Check if lockfiles exist."""
    lockfiles = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
        "Pipfile.lock", "poetry.lock", "pdm.lock",
        "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock",
    ]
    return any((root / lf).exists() for lf in lockfiles)


def check_pinned_versions(deps: list[DependencyInfo]) -> bool:
    """Check if dependencies have pinned versions."""
    if not deps:
        return True
    pinned = sum(1 for d in deps if d.version and d.version not in ("unpinned", "*", "latest"))
    return pinned / len(deps) > 0.7


def scan_quality_signals(root: Path, files: list[FileInfo]) -> dict:
    """Check for project quality indicators."""
    filenames = {f.path.name.lower() for f in files}
    rel_paths = {str(f.path.relative_to(root)) for f in files}

    result = {
        "has_readme": any(n.startswith("readme") for n in filenames),
        "has_license": any(n.startswith("licen") for n in filenames),
        "has_gitignore": (root / ".gitignore").exists(),
        "has_ci": any(".github/workflows" in p or ".gitlab-ci" in p or "Jenkinsfile" in p for p in rel_paths),
        "has_docker": any(n in ("dockerfile", "docker-compose.yml", "docker-compose.yaml") for n in filenames),
        "has_env_example": any(n in (".env.example", ".env.sample", ".env.template", "env.example") for n in filenames),
        "has_contributing": any(n.startswith("contributing") for n in filenames),
        "has_changelog": any(n.startswith("changelog") or n.startswith("changes") for n in filenames),
        "has_editorconfig": (root / ".editorconfig").exists(),
        "has_linter_config": any(
            n in (".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.yml",
                  ".flake8", ".pylintrc", "pylintrc", ".ruff.toml", "ruff.toml",
                  ".rubocop.yml", ".golangci.yml", "biome.json", "biome.jsonc")
            for n in filenames
        ),
        "has_formatter_config": any(
            n in (".prettierrc", ".prettierrc.js", ".prettierrc.json",
                  "pyproject.toml", ".clang-format", ".editorconfig",
                  ".rustfmt.toml", "biome.json")
            for n in filenames
        ),
        "has_type_checking": any(
            n in ("tsconfig.json", "mypy.ini", ".mypy.ini", "py.typed")
            for n in filenames
        ) or any("mypy" in p or "pyright" in p for p in rel_paths),
    }

    # Test detection
    test_patterns = re.compile(r"(test_|_test\.|\.test\.|\.spec\.|tests\.py|conftest)")
    test_dirs = {"tests", "test", "__tests__", "spec", "specs"}
    test_files = [
        f for f in files
        if test_patterns.search(f.path.name.lower())
        or any(td in f.path.parts for td in test_dirs)
    ]
    result["has_tests"] = len(test_files) > 0
    result["test_file_count"] = len(test_files)

    code_files = [f for f in files if f.extension in LANG_MAP and f.extension not in {".md", ".json", ".yaml", ".yml", ".xml", ".toml"}]
    result["test_ratio"] = len(test_files) / max(len(code_files), 1)

    return result


def scan_security(root: Path, files: list[FileInfo]) -> list[SecurityFinding]:
    """Scan for common security issues."""
    findings = []

    # Check for secrets in common files
    secret_patterns = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{20,}', "API key"),
        (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}', "Hardcoded secret/password"),
        (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']?AK[A-Z0-9]{18}', "AWS access key"),
        (r'(?i)(aws_secret_access_key)\s*[=:]\s*["\']?[a-zA-Z0-9/+=]{40}', "AWS secret key"),
        (r'(?i)ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
        (r'(?i)sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe secret key"),
        (r'(?i)(private[_-]?key)\s*[=:]\s*["\'][^"\']{20,}', "Private key reference"),
    ]

    sensitive_files = [
        f for f in files
        if f.extension in {".py", ".js", ".ts", ".env", ".cfg", ".ini", ".yaml", ".yml", ".json", ".toml", ".rb", ".php"}
        and f.size < 500_000  # skip huge files
    ]

    for finfo in sensitive_files[:200]:  # cap to prevent slow scans
        try:
            content = finfo.path.read_text(errors="ignore")
            for pattern, desc in secret_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append(SecurityFinding(
                        severity="critical",
                        category="Hardcoded Secret",
                        message=f"Potential {desc} found",
                        file=str(finfo.path.relative_to(root)),
                        line=line_num,
                    ))
        except (OSError, UnicodeDecodeError):
            continue

    # Check for .env file committed
    if (root / ".env").exists():
        findings.append(SecurityFinding(
            severity="critical",
            category="Exposed Config",
            message=".env file exists in project root — likely contains secrets",
            file=".env",
        ))

    # Check if .env is in .gitignore
    gitignore = root / ".gitignore"
    if gitignore.exists():
        try:
            gi_content = gitignore.read_text()
            if ".env" not in gi_content:
                findings.append(SecurityFinding(
                    severity="high",
                    category="Missing Gitignore Rule",
                    message=".env is NOT listed in .gitignore — secrets may be committed",
                    file=".gitignore",
                ))
        except OSError:
            pass
    else:
        findings.append(SecurityFinding(
            severity="medium",
            category="Missing File",
            message="No .gitignore file found — risk of committing secrets and build artifacts",
        ))

    # Check for debug/development flags in code
    for finfo in sensitive_files[:100]:
        try:
            content = finfo.path.read_text(errors="ignore")
            if re.search(r'(?i)DEBUG\s*=\s*True', content):
                findings.append(SecurityFinding(
                    severity="medium",
                    category="Debug Mode",
                    message="DEBUG = True found — ensure this is disabled in production",
                    file=str(finfo.path.relative_to(root)),
                ))
        except (OSError, UnicodeDecodeError):
            continue

    # Check for TODO/FIXME/HACK comments as technical debt signals
    debt_count = 0
    for finfo in sensitive_files[:100]:
        try:
            content = finfo.path.read_text(errors="ignore")
            debt_count += len(re.findall(r'(?i)#\s*(TODO|FIXME|HACK|XXX|TEMP)\b', content))
        except (OSError, UnicodeDecodeError):
            continue

    if debt_count > 10:
        findings.append(SecurityFinding(
            severity="info",
            category="Technical Debt",
            message=f"{debt_count} TODO/FIXME/HACK comments found across the codebase",
        ))

    return findings


def detect_dead_files(root: Path, files: list[FileInfo]) -> list[str]:
    """Detect potentially orphaned or dead files."""
    dead = []
    for f in files:
        name = f.path.name.lower()
        # Temp files
        if name.endswith((".bak", ".tmp", ".temp", ".swp", ".swo", ".orig")):
            dead.append(str(f.path.relative_to(root)))
        # OS junk
        elif name in (".ds_store", "thumbs.db"):
            dead.append(str(f.path.relative_to(root)))
        # Log files in source
        elif f.extension == ".log" and f.size > 0:
            dead.append(str(f.path.relative_to(root)))
        # Empty files (non-special)
        elif f.size == 0 and f.extension in LANG_MAP and name != "__init__.py":
            dead.append(str(f.path.relative_to(root)))
    return dead[:20]


# ─── Scoring ─────────────────────────────────────────────────────────

def calculate_scores(report: HealthReport) -> None:
    """Calculate health scores across dimensions."""

    # Structure Score (0-100)
    s = 0
    if report.has_readme: s += 20
    if report.has_license: s += 10
    if report.has_gitignore: s += 15
    if report.has_changelog: s += 5
    if report.has_contributing: s += 5
    if report.has_editorconfig: s += 5
    if report.has_env_example: s += 5
    if report.total_lines > 0: s += 10
    if len(report.languages) >= 1: s += 10
    if report.frameworks: s += 5
    if report.has_docker: s += 5
    if len(report.potentially_dead) == 0: s += 5
    report.structure_score = min(100, s)

    # Quality Score (0-100)
    q = 0
    if report.has_tests: q += 25
    if report.test_ratio > 0.1: q += 10
    if report.test_ratio > 0.3: q += 5
    if report.has_ci: q += 20
    if report.has_linter_config: q += 10
    if report.has_formatter_config: q += 10
    if report.has_type_checking: q += 10
    if report.has_readme: q += 5
    if report.has_contributing: q += 5
    report.quality_score = min(100, q)

    # Security Score (0-100)
    critical = sum(1 for f in report.security_findings if f.severity == "critical")
    high = sum(1 for f in report.security_findings if f.severity == "high")
    medium = sum(1 for f in report.security_findings if f.severity == "medium")
    sec = 100
    sec -= critical * 25
    sec -= high * 15
    sec -= medium * 5
    report.security_score = max(0, min(100, sec))

    # Dependency Score (0-100)
    d = 50  # baseline
    if report.has_lockfile: d += 20
    if report.has_pinned_versions: d += 15
    if report.dependencies:
        d += 10  # has declared deps
        unpinned = sum(1 for dep in report.dependencies if dep.version in ("unpinned", "*", "latest"))
        if unpinned > len(report.dependencies) * 0.3:
            d -= 15
    else:
        d += 5  # no deps = no dep problems
    report.dependency_score = max(0, min(100, d))

    # Overall
    weights = {
        "structure": 0.25,
        "quality": 0.30,
        "security": 0.30,
        "dependency": 0.15,
    }
    report.overall_score = int(
        report.structure_score * weights["structure"]
        + report.quality_score * weights["quality"]
        + report.security_score * weights["security"]
        + report.dependency_score * weights["dependency"]
    )

    if report.overall_score >= 90: report.overall_grade = "A+"
    elif report.overall_score >= 80: report.overall_grade = "A"
    elif report.overall_score >= 70: report.overall_grade = "B"
    elif report.overall_score >= 60: report.overall_grade = "C"
    elif report.overall_score >= 50: report.overall_grade = "D"
    else: report.overall_grade = "F"


# ─── Report Assembly ──────────────────────────────────────────────────

def build_report(root: Path) -> HealthReport:
    """Run all scanners and assemble the health report."""
    report = HealthReport(
        project_name=root.resolve().name,
        scan_time=datetime.now().isoformat(timespec="seconds"),
        root=root,
    )

    files = scan_files(root)
    report.total_files = len(files)
    report.total_dirs = len(set(f.path.parent for f in files))
    report.total_lines = sum(f.lines for f in files)
    report.total_size_bytes = sum(f.size for f in files)

    report.languages = detect_languages(files)
    report.frameworks = detect_frameworks(root)

    ext_counter = Counter(f.extension for f in files if f.extension)
    report.file_types = dict(ext_counter.most_common(15))

    report.largest_files = [
        {"path": str(f.path.relative_to(root)), "size": f.size, "lines": f.lines}
        for f in sorted(files, key=lambda f: f.size, reverse=True)[:10]
    ]

    report.dependencies = parse_dependencies(root)
    report.has_lockfile = check_lockfiles(root)
    report.has_pinned_versions = check_pinned_versions(report.dependencies)

    quality = scan_quality_signals(root, files)
    for key, val in quality.items():
        setattr(report, key, val)

    report.security_findings = scan_security(root, files)
    report.potentially_dead = detect_dead_files(root, files)

    calculate_scores(report)
    return report


# ─── Terminal Output ──────────────────────────────────────────────────

def print_report(report: HealthReport) -> None:
    """Print beautiful terminal report."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    def score_color(score: int) -> str:
        if score >= 80: return "green"
        if score >= 60: return "yellow"
        return "red"

    # Header
    grade_color = score_color(report.overall_score)
    header = Text()
    header.append("🏥 CODEVITAL", style="bold magenta")
    header.append(f"  —  Health Report\n\n", style="dim")
    header.append(f"Project: ", style="bold")
    header.append(f"{report.project_name}\n", style="cyan")
    header.append(f"Scanned: {report.scan_time}\n\n", style="dim")
    header.append(f"Overall Health: ", style="bold")
    header.append(f"{report.overall_grade} ", style=f"bold {grade_color}")
    header.append(f"({report.overall_score}/100)", style=grade_color)
    console.print(Panel(header, border_style="magenta", expand=False))

    # Score breakdown
    console.print("\n[bold magenta]📊 SCORE BREAKDOWN[/]\n")
    scores = [
        ("Structure", report.structure_score, "📁"),
        ("Quality", report.quality_score, "✨"),
        ("Security", report.security_score, "🛡️"),
        ("Dependencies", report.dependency_score, "📦"),
    ]
    for name, score, icon in scores:
        color = score_color(score)
        bar_len = score // 3
        bar = "█" * bar_len + "░" * (33 - bar_len)
        console.print(f"  {icon} {name:<14} [{color}]{bar}[/] [{color}]{score}/100[/]")
    console.print()

    # Project overview
    def fmt_size(b: int) -> str:
        if b < 1024: return f"{b} B"
        if b < 1024**2: return f"{b/1024:.1f} KB"
        if b < 1024**3: return f"{b/1024**2:.1f} MB"
        return f"{b/1024**3:.1f} GB"

    console.print("[bold magenta]📁 PROJECT OVERVIEW[/]\n")
    ov_table = Table(show_header=False, border_style="cyan")
    ov_table.add_column("Metric", style="bold", width=20)
    ov_table.add_column("Value", style="cyan")
    ov_table.add_row("Total files", f"{report.total_files:,}")
    ov_table.add_row("Total directories", f"{report.total_dirs:,}")
    ov_table.add_row("Total lines", f"{report.total_lines:,}")
    ov_table.add_row("Total size", fmt_size(report.total_size_bytes))
    if report.frameworks:
        ov_table.add_row("Frameworks", ", ".join(report.frameworks))
    console.print(ov_table)
    console.print()

    # Languages
    if report.languages:
        console.print("[bold magenta]💻 LANGUAGES[/]\n")
        total_lines = sum(v["lines"] for v in report.languages.values())
        l_table = Table(border_style="green")
        l_table.add_column("Language", style="bold")
        l_table.add_column("Files", justify="right")
        l_table.add_column("Lines", justify="right", style="cyan")
        l_table.add_column("Share", justify="right")
        for lang, data in list(report.languages.items())[:10]:
            share = f"{data['lines'] / max(total_lines, 1) * 100:.1f}%"
            l_table.add_row(lang, str(data["files"]), f"{data['lines']:,}", share)
        console.print(l_table)
        console.print()

    # Quality checklist
    console.print("[bold magenta]✅ QUALITY CHECKLIST[/]\n")
    checks = [
        ("README", report.has_readme, "high"),
        ("LICENSE", report.has_license, "high"),
        (".gitignore", report.has_gitignore, "high"),
        ("CI/CD Pipeline", report.has_ci, "high"),
        ("Tests", report.has_tests, "high"),
        ("Linter config", report.has_linter_config, "medium"),
        ("Formatter config", report.has_formatter_config, "medium"),
        ("Type checking", report.has_type_checking, "medium"),
        ("Docker", report.has_docker, "low"),
        (".env.example", report.has_env_example, "medium"),
        ("CONTRIBUTING", report.has_contributing, "low"),
        ("CHANGELOG", report.has_changelog, "low"),
        (".editorconfig", report.has_editorconfig, "low"),
    ]
    for name, present, importance in checks:
        icon = "[green]✅[/]" if present else "[red]❌[/]"
        imp = {"high": "[red](important)[/]", "medium": "[yellow](recommended)[/]", "low": "[dim](nice to have)[/]"}
        suffix = "" if present else f" {imp[importance]}"
        console.print(f"  {icon} {name}{suffix}")

    if report.has_tests:
        console.print(f"\n  Test files: {report.test_file_count}  |  Test ratio: {report.test_ratio:.1%}")
    console.print()

    # Dependencies
    if report.dependencies:
        console.print("[bold magenta]📦 DEPENDENCIES[/]\n")
        prod_deps = [d for d in report.dependencies if not d.is_dev]
        dev_deps = [d for d in report.dependencies if d.is_dev]
        console.print(f"  Production: {len(prod_deps)}  |  Dev: {len(dev_deps)}")
        console.print(f"  Lockfile: {'[green]✅ Present[/]' if report.has_lockfile else '[red]❌ Missing[/]'}")
        console.print(f"  Pinned versions: {'[green]✅ Yes[/]' if report.has_pinned_versions else '[yellow]⚠️ Many unpinned[/]'}")
        console.print()

    # Security
    if report.security_findings:
        console.print("[bold magenta]🛡️ SECURITY FINDINGS[/]\n")
        severity_counts = Counter(f.severity for f in report.security_findings)
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan"}.get(sev, "dim")
                console.print(f"  [{sev_color}]{sev.upper()}: {count}[/]")

        s_table = Table(border_style="red")
        s_table.add_column("Severity", width=10)
        s_table.add_column("Category", style="bold")
        s_table.add_column("Message")
        s_table.add_column("Location", style="dim")
        for finding in report.security_findings[:15]:
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan"}.get(finding.severity, "dim")
            loc = finding.file
            if finding.line:
                loc += f":{finding.line}"
            s_table.add_row(f"[{sev_color}]{finding.severity.upper()}[/]", finding.category, finding.message, loc)
        console.print(s_table)
        console.print()
    else:
        console.print("[bold green]🛡️ No security issues detected![/]\n")

    # Dead files
    if report.potentially_dead:
        console.print("[bold magenta]🗑️ POTENTIALLY DEAD FILES[/]\n")
        for f in report.potentially_dead[:10]:
            console.print(f"  [dim]• {f}[/]")
        console.print()

    # Recommendations
    console.print("[bold magenta]💡 TOP RECOMMENDATIONS[/]\n")
    recs = []
    if not report.has_readme:
        recs.append(("🔴", "Add a README.md — it's the first thing people see"))
    if not report.has_license:
        recs.append(("🔴", "Add a LICENSE file — without one, your code is technically all-rights-reserved"))
    if not report.has_gitignore:
        recs.append(("🔴", "Add a .gitignore — you may be committing build artifacts and secrets"))
    if not report.has_tests:
        recs.append(("🔴", "Add tests — even a few smoke tests dramatically improve confidence"))
    if not report.has_ci:
        recs.append(("🟡", "Set up CI/CD — GitHub Actions is free for public repos"))
    if not report.has_lockfile and report.dependencies:
        recs.append(("🟡", "Add a lockfile — pin your dependency tree for reproducible builds"))
    if not report.has_linter_config:
        recs.append(("🟡", "Add a linter — catches bugs before they reach production"))
    if not report.has_env_example:
        recs.append(("🟢", "Add .env.example — helps new contributors set up quickly"))
    critical_secs = [f for f in report.security_findings if f.severity == "critical"]
    if critical_secs:
        recs.append(("🔴", f"Fix {len(critical_secs)} critical security finding(s) — possible exposed secrets"))
    if report.potentially_dead:
        recs.append(("🟢", f"Clean up {len(report.potentially_dead)} dead/temp files"))

    if recs:
        for icon, msg in recs[:8]:
            console.print(f"  {icon} {msg}")
    else:
        console.print("  [green]🎉 Your project looks great! No major recommendations.[/]")
    console.print()

    console.print(Panel(
        "[dim]Generated by[/] [bold magenta]codevital[/] [dim]— the complete health check for any codebase[/]",
        border_style="dim",
        expand=False,
    ))


# ─── HTML Report ──────────────────────────────────────────────────────

def generate_html(report: HealthReport, output: Path) -> None:
    """Generate standalone HTML report."""
    def score_class(s: int) -> str:
        if s >= 80: return "good"
        if s >= 60: return "warn"
        return "bad"

    def fmt_size(b: int) -> str:
        if b < 1024: return f"{b} B"
        if b < 1024**2: return f"{b/1024:.1f} KB"
        if b < 1024**3: return f"{b/1024**2:.1f} MB"
        return f"{b/1024**3:.1f} GB"

    # Language bars
    total_lines = sum(v["lines"] for v in report.languages.values()) or 1
    lang_bars = ""
    colors = ["#7c3aed","#06b6d4","#22c55e","#eab308","#ef4444","#d946ef","#f97316","#14b8a6","#8b5cf6","#ec4899"]
    for i, (lang, data) in enumerate(list(report.languages.items())[:8]):
        pct = data["lines"] / total_lines * 100
        c = colors[i % len(colors)]
        lang_bars += f'<div class="lang-bar" style="width:{max(pct,2)}%;background:{c}" title="{lang}: {pct:.1f}%"></div>'

    lang_legend = ""
    for i, (lang, data) in enumerate(list(report.languages.items())[:8]):
        c = colors[i % len(colors)]
        pct = data["lines"] / total_lines * 100
        lang_legend += f'<span class="lang-tag"><span class="lang-dot" style="background:{c}"></span>{lang} {pct:.0f}%</span>'

    # Checklist
    checks = [
        ("README", report.has_readme), ("LICENSE", report.has_license),
        (".gitignore", report.has_gitignore), ("CI/CD", report.has_ci),
        ("Tests", report.has_tests), ("Linter", report.has_linter_config),
        ("Formatter", report.has_formatter_config), ("Type Checking", report.has_type_checking),
        ("Docker", report.has_docker), (".env.example", report.has_env_example),
        ("CONTRIBUTING", report.has_contributing), ("CHANGELOG", report.has_changelog),
    ]
    check_html = ""
    for name, present in checks:
        icon = "✅" if present else "❌"
        cls = "pass" if present else "fail"
        check_html += f'<div class="check-item {cls}">{icon} {name}</div>'

    # Security findings
    sec_html = ""
    if report.security_findings:
        rows = ""
        for f in report.security_findings[:15]:
            loc = f.file
            if f.line: loc += f":{f.line}"
            rows += f'<tr><td class="sev-{f.severity}">{f.severity.upper()}</td><td>{f.category}</td><td>{f.message}</td><td class="dim">{loc}</td></tr>'
        sec_html = f'<table><thead><tr><th>Severity</th><th>Category</th><th>Message</th><th>Location</th></tr></thead><tbody>{rows}</tbody></table>'
    else:
        sec_html = '<p class="all-clear">🎉 No security issues detected!</p>'

    # Recommendations
    recs_html = ""
    recs = []
    if not report.has_readme: recs.append("Add a README.md")
    if not report.has_license: recs.append("Add a LICENSE file")
    if not report.has_gitignore: recs.append("Add a .gitignore")
    if not report.has_tests: recs.append("Add tests")
    if not report.has_ci: recs.append("Set up CI/CD")
    if not report.has_lockfile and report.dependencies: recs.append("Add a dependency lockfile")
    critical = [f for f in report.security_findings if f.severity == "critical"]
    if critical: recs.append(f"Fix {len(critical)} critical security issue(s)")
    for r in recs[:6]:
        recs_html += f'<div class="rec-item">→ {r}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeVital — {report.project_name}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Instrument+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{{--bg:#05050a;--s:#0c0c18;--s2:#14142a;--b:#222244;--t:#e0e0f0;--d:#555580;--a:#7c3aed;--a2:#06b6d4;--g:#22c55e;--r:#ef4444;--y:#eab308;--m:#d946ef}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--t);font-family:'Instrument Sans',sans-serif;padding:2rem;max-width:960px;margin:0 auto;line-height:1.6}}
.hero{{text-align:center;padding:2.5rem 1rem;border-bottom:1px solid var(--b);margin-bottom:2rem}}
.hero h1{{font-size:2.4rem;font-weight:800;background:linear-gradient(135deg,var(--a),var(--m),var(--a2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.hero .pname{{font-family:'IBM Plex Mono',monospace;color:var(--a2);font-size:1.1rem;margin:.5rem 0}}
.hero .meta{{color:var(--d);font-size:.85rem}}
.grade-ring{{display:inline-flex;align-items:center;justify-content:center;width:90px;height:90px;border-radius:50%;border:4px solid;font-family:'IBM Plex Mono',monospace;font-size:2.2rem;font-weight:700;margin:1rem}}
.grade-ring.good{{border-color:var(--g);color:var(--g)}}
.grade-ring.warn{{border-color:var(--y);color:var(--y)}}
.grade-ring.bad{{border-color:var(--r);color:var(--r)}}
.scores{{display:grid;grid-template-columns:repeat(4,1fr);gap:.8rem;margin:1.5rem 0}}
.score-card{{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:1rem;text-align:center}}
.score-card .num{{font-family:'IBM Plex Mono',monospace;font-size:1.6rem;font-weight:700}}
.score-card .lbl{{font-size:.7rem;color:var(--d);text-transform:uppercase;letter-spacing:1px;margin-top:.3rem}}
.card{{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:1.3rem;margin-bottom:1rem}}
.card h3{{font-size:1rem;font-weight:700;margin-bottom:.8rem}}
.lang-track{{display:flex;height:10px;border-radius:5px;overflow:hidden;gap:2px;margin:.8rem 0}}
.lang-bar{{border-radius:3px;min-width:8px;transition:width .5s}}
.lang-legend{{display:flex;flex-wrap:wrap;gap:.6rem;margin-top:.5rem}}
.lang-tag{{font-size:.75rem;display:flex;align-items:center;gap:.3rem}}
.lang-dot{{width:8px;height:8px;border-radius:50%;display:inline-block}}
.kv-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.4rem}}
.kv{{display:flex;justify-content:space-between;padding:.35rem .6rem;background:var(--s2);border-radius:6px;font-size:.85rem}}
.kv span:first-child{{color:var(--d)}}.kv span:last-child{{font-family:'IBM Plex Mono',monospace;font-weight:600}}
.check-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:.4rem}}
.check-item{{padding:.4rem .6rem;background:var(--s2);border-radius:6px;font-size:.82rem}}
.check-item.pass{{border-left:3px solid var(--g)}}.check-item.fail{{border-left:3px solid var(--r)}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead th{{text-align:left;padding:.5rem;border-bottom:2px solid var(--b);color:var(--d);font-size:.72rem;text-transform:uppercase;letter-spacing:.5px}}
tbody td{{padding:.4rem .5rem;border-bottom:1px solid var(--b);font-family:'IBM Plex Mono',monospace;font-size:.78rem}}
.sev-critical{{color:var(--r);font-weight:700}}.sev-high{{color:#f97316}}.sev-medium{{color:var(--y)}}.sev-low,.sev-info{{color:var(--d)}}
.dim{{color:var(--d);font-family:'Instrument Sans',sans-serif}}
.all-clear{{color:var(--g);font-size:1rem;text-align:center;padding:1rem}}
.rec-item{{padding:.5rem .7rem;margin:.3rem 0;background:var(--s2);border-radius:6px;border-left:3px solid var(--a);font-size:.85rem}}
.good{{color:var(--g)}}.warn{{color:var(--y)}}.bad{{color:var(--r)}}
footer{{text-align:center;padding:2rem;color:var(--d);font-size:.8rem;border-top:1px solid var(--b);margin-top:2rem}}
footer a{{color:var(--a);text-decoration:none}}
@media(max-width:600px){{.scores{{grid-template-columns:1fr 1fr}}.check-grid{{grid-template-columns:1fr 1fr}}.kv-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="hero">
<h1>🏥 CodeVital</h1>
<div class="pname">{report.project_name}</div>
<div class="grade-ring {score_class(report.overall_score)}">{report.overall_grade}</div>
<div class="meta">{report.overall_score}/100 · Scanned {report.scan_time}</div>
</div>
<div class="scores">
<div class="score-card"><div class="num {score_class(report.structure_score)}">{report.structure_score}</div><div class="lbl">📁 Structure</div></div>
<div class="score-card"><div class="num {score_class(report.quality_score)}">{report.quality_score}</div><div class="lbl">✨ Quality</div></div>
<div class="score-card"><div class="num {score_class(report.security_score)}">{report.security_score}</div><div class="lbl">🛡️ Security</div></div>
<div class="score-card"><div class="num {score_class(report.dependency_score)}">{report.dependency_score}</div><div class="lbl">📦 Deps</div></div>
</div>
<div class="card"><h3>📁 Overview</h3>
<div class="kv-grid">
<div class="kv"><span>Files</span><span>{report.total_files:,}</span></div>
<div class="kv"><span>Lines</span><span>{report.total_lines:,}</span></div>
<div class="kv"><span>Size</span><span>{fmt_size(report.total_size_bytes)}</span></div>
<div class="kv"><span>Frameworks</span><span>{', '.join(report.frameworks) or '—'}</span></div>
</div></div>
<div class="card"><h3>💻 Languages</h3>
<div class="lang-track">{lang_bars}</div>
<div class="lang-legend">{lang_legend}</div></div>
<div class="card"><h3>✅ Quality Checklist</h3>
<div class="check-grid">{check_html}</div></div>
<div class="card"><h3>🛡️ Security</h3>{sec_html}</div>
{"<div class='card'><h3>💡 Recommendations</h3>" + recs_html + "</div>" if recs_html else ""}
<footer>Generated by <a href="https://github.com/YOUR_USERNAME/codevital">codevital</a> — the complete health check for any codebase</footer>
</body></html>"""

    output.write_text(html)
    print(f"📄 HTML report saved to {output}")


# ─── CLI ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CodeVital — The complete health check for any codebase.",
    )
    parser.add_argument(
        "folder", type=Path, nargs="?", default=Path("."),
        help="Project folder to scan (defaults to current directory)",
    )
    parser.add_argument(
        "--html", type=Path, default=None,
        help="Generate a standalone HTML report",
    )
    parser.add_argument(
        "--json", type=Path, default=None,
        help="Export raw results as JSON",
    )
    args = parser.parse_args()

    root = args.folder.resolve()
    if not root.is_dir():
        print(f"❌ Not a valid directory: {root}")
        sys.exit(1)

    from rich.console import Console
    console = Console()
    with console.status(f"[cyan]Scanning {root.name}…[/]"):
        report = build_report(root)

    print_report(report)

    if args.html:
        generate_html(report, args.html)

    if args.json:
        data = {
            "project": report.project_name,
            "scan_time": report.scan_time,
            "scores": {
                "overall": report.overall_score,
                "grade": report.overall_grade,
                "structure": report.structure_score,
                "quality": report.quality_score,
                "security": report.security_score,
                "dependency": report.dependency_score,
            },
            "stats": {
                "files": report.total_files,
                "lines": report.total_lines,
                "size_bytes": report.total_size_bytes,
            },
            "languages": report.languages,
            "frameworks": report.frameworks,
            "security_findings": [
                {"severity": f.severity, "category": f.category, "message": f.message, "file": f.file}
                for f in report.security_findings
            ],
        }
        args.json.write_text(json.dumps(data, indent=2))
        print(f"📋 JSON report saved to {args.json}")


if __name__ == "__main__":
    main()
