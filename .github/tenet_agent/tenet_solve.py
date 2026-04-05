"""
TENET Agent - Issue Solver
Triggered by: tenet-issue-solver.yml on issue_comment events (/tenet fix).

Flow:
  1. Reads the issue title + body
  2. Scans the repository for relevant source files
  3. Calls Gemini (analysis phase) to plan the fix
  4. Calls Gemini (code generation phase) to produce file changes
  5. Parses the LLM output into {filepath: content} map
  6. Creates a branch, commits changes, and opens a PR
  7. Posts a summary comment on the original issue
"""

import os
import re
import sys
import json
from pathlib import Path

from github import GithubException

from utils import (
    get_github_client,
    get_repo,
    get_llm_client,
    call_llm,
    get_repo_structure,
    read_relevant_files,
    post_issue_comment,
    create_branch_and_commit,
)
from prompts import (
    ISSUE_SOLVER_ANALYSIS_TEMPLATE,
    ISSUE_SOLVER_CODE_TEMPLATE,
    ISSUE_SOLVER_PR_BODY_TEMPLATE,
)

# Allowed source file extensions for LLM-proposed paths
_ALLOWED_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".jsx",
    ".json", ".yaml", ".yml", ".md", ".txt", ".env.example",
}


# ─── Parsing helpers ──────────────────────────────────────────────────────────

def _safe_filepath(filepath: str, repo_root: Path) -> str | None:
    """
    Validate and normalise a filepath proposed by the LLM.

    Returns the normalised relative path string if safe, or None if the path
    should be rejected (traversal attempt, .git write, disallowed extension).
    """
    filepath = filepath.strip()
    if not filepath:
        return None

    # Block disallowed extensions
    suffix = Path(filepath).suffix.lower()
    if suffix and suffix not in _ALLOWED_EXTENSIONS:
        print(f"⚠️  Skipping disallowed file extension from LLM output: {filepath!r}")
        return None

    candidate = (repo_root / filepath).resolve()

    # Reject anything that escapes the repo root or touches .git
    if not candidate.is_relative_to(repo_root) or ".git" in candidate.parts:
        print(f"⚠️  Skipping unsafe path from LLM output: {filepath!r}")
        return None

    return str(candidate.relative_to(repo_root))


def parse_file_changes(llm_output: str) -> dict[str, str] | None:
    """
    Parse the LLM's output into a dict of {filepath: content}.

    Tries three patterns in order of strictness:
      1. Primary   — ``### FILE: path`` (exact format requested in the prompt)
      2. Tolerant  — ``## / ### / #### FILE:`` case-insensitive (common LLM drift)
      3. Bold header — ``**path/to/file.ext**`` followed by a fenced block
                       (Gemini's default prose formatting)

    Returns None  if the LLM flagged CANNOT_FIX.
    Returns {}    if no parseable file blocks were found after all patterns.

    All filepaths are validated via _safe_filepath() to prevent path traversal.
    """
    if "### CANNOT_FIX" in llm_output:
        return None

    # ── Pattern 1: exact ### FILE: (prompt-specified format) ──────────────────
    primary = re.compile(
        r"###\s*FILE:\s*([^\n]+)\n```[^\n]*\n(.*?)```",
        re.DOTALL,
    )
    matches = primary.findall(llm_output)

    # ── Pattern 2: tolerant header level + case-insensitive FILE label ─────────
    if not matches:
        tolerant = re.compile(
            r"#{1,4}\s*FILE:\s*([^\n]+)\n```[^\n]*\n(.*?)```",
            re.DOTALL | re.IGNORECASE,
        )
        matches = tolerant.findall(llm_output)

    # ── Pattern 3: bold filename header (Gemini prose default) ────────────────
    if not matches:
        bold_header = re.compile(
            r"\*\*([^\n*]+\.(?:py|ts|tsx|js|jsx|json|ya?ml|md|txt))\*\*\s*\n"
            r"```[^\n]*\n(.*?)```",
            re.DOTALL,
        )
        matches = bold_header.findall(llm_output)

    if not matches:
        print("⚠️  parse_file_changes: no FILE blocks matched any pattern.")
        print("─── RAW LLM OUTPUT (first 2000 chars) ───")
        print(llm_output[:2000])
        print("──────────────────────────────────────────")
        return {}

    repo_root = Path(".").resolve()
    changes: dict[str, str] = {}

    for filepath, content in matches:
        safe = _safe_filepath(filepath, repo_root)
        if safe is None:
            continue
        content = content.rstrip()
        if content:
            changes[safe] = content

    return changes


def extract_commit_message(llm_output: str, fallback: str) -> str:
    """Extract the commit message line from the LLM output."""
    match = re.search(r"\*\*Commit Message\*\*[:\s]+(.+)", llm_output)
    if match:
        return match.group(1).strip().strip("`\"'")
    return fallback


# ─── Main flow ────────────────────────────────────────────────────────────────

def main():
    """Run the TENET Agent issue-solver workflow."""
    print("🛡️  TENET Agent - Issue Solver starting...")

    # ── Gather context ─────────────────────────────────────────────────────────
    issue_number = int(os.environ["ISSUE_NUMBER"])
    issue_title = os.environ.get("ISSUE_TITLE", "")
    issue_body = os.environ.get("ISSUE_BODY", "") or ""
    issue_labels_raw = os.environ.get("ISSUE_LABELS", "[]")
    triggered_by = os.environ.get("TRIGGERED_BY", "a maintainer")

    try:
        labels_data = json.loads(issue_labels_raw)
        issue_labels = ", ".join(lbl.get("name", "") for lbl in labels_data) or "none"
    except Exception:
        issue_labels = "none"

    print(f"📋 Issue #{issue_number}: {issue_title}")
    print(f"🔖 Labels: {issue_labels}")
    print(f"👤 Triggered by: @{triggered_by}")

    g = get_github_client()
    repo = get_repo(g)
    model = get_llm_client()

    branch_name = f"tenet/fix-issue-{issue_number}"

    # ── Scan repo ──────────────────────────────────────────────────────────────
    print("🔍 Scanning repository structure...")
    repo_structure = get_repo_structure(".")
    print("📁 Reading relevant source files...")
    relevant_files = read_relevant_files(issue_title, issue_body)

    # ── Phase 1: Analysis ──────────────────────────────────────────────────────
    print("🧠 Phase 1: Asking Gemini to analyze the issue...")
    analysis_prompt = ISSUE_SOLVER_ANALYSIS_TEMPLATE.format(
        issue_number=issue_number,
        issue_title=issue_title,
        issue_body=issue_body or "*No description provided.*",
        issue_labels=issue_labels,
        repo_structure=repo_structure,
        relevant_files=relevant_files,
    )
    analysis = call_llm(model, analysis_prompt)
    print("📝 Analysis complete.")

    # ── Phase 2: Code generation ───────────────────────────────────────────────
    print("💻 Phase 2: Asking Gemini to generate the fix...")
    code_prompt = ISSUE_SOLVER_CODE_TEMPLATE.format(
        issue_number=issue_number,
        issue_title=issue_title,
        analysis=analysis,
        relevant_files=relevant_files,
    )
    code_output = call_llm(model, code_prompt)
    print("✍️  Code generation complete.")

    # ── Debug: log raw output header to aid future parse failures ─────────────
    print("─── RAW LLM OUTPUT (first 500 chars) ────")
    print((code_output or "")[:500])
    print("─────────────────────────────────────────")

    # ── Parse file changes ─────────────────────────────────────────────────────
    file_changes = parse_file_changes(code_output)

    if file_changes is None:
        # LLM said it cannot fix this issue
        cannot_fix_reason = re.sub(
            r".*### CANNOT_FIX\s*", "", code_output, flags=re.DOTALL
        ).strip()
        comment = (
            f"## 🤖 TENET Agent - Cannot Auto-Fix\n\n"
            f"After analyzing issue #{issue_number}, TENET Agent determined it cannot "
            f"generate an automated fix for the following reason:\n\n"
            f"{cannot_fix_reason}\n\n"
            f"**Manual intervention is required.** Please provide more details or "
            f"assign a contributor to resolve this issue.\n\n"
            f"---\n*TENET Agent 🛡️*"
        )
        post_issue_comment(repo, issue_number, comment)
        print("ℹ️  Agent flagged CANNOT_FIX. Commented on issue and exiting.")
        sys.exit(0)

    if not file_changes:
        comment = (
            f"## 🤖 TENET Agent - Fix Generation Failed\n\n"
            f"TENET Agent was unable to parse a valid code fix from the LLM response "
            f"for issue #{issue_number}. The LLM may have misunderstood the request.\n\n"
            f"**Analysis:**\n{analysis}\n\n"
            f"---\n*TENET Agent 🛡️*"
        )
        post_issue_comment(repo, issue_number, comment)
        print("⚠️  No file changes parsed. Commented on issue and exiting.")
        sys.exit(1)

    print(f"📦 Files to update: {list(file_changes.keys())}")

    # ── Commit and push ────────────────────────────────────────────────────────
    commit_message_default = f"fix: auto-fix issue #{issue_number} via TENET Agent"
    commit_message = extract_commit_message(code_output, commit_message_default)
    print(f"🔧 Commit message: {commit_message}")

    success = create_branch_and_commit(branch_name, file_changes, commit_message)
    if not success:
        post_issue_comment(
            repo,
            issue_number,
            f"## 🤖 TENET Agent - Branch Push Failed\n\n"
            f"TENET Agent generated a fix for issue #{issue_number} but encountered "
            f"a git error when pushing the branch `{branch_name}`.\n\n"
            f"Please check the Actions run logs for details.\n\n---\n*TENET Agent 🛡️*",
        )
        sys.exit(1)

    # ── Open PR ────────────────────────────────────────────────────────────────
    print("🚀 Opening PR...")
    files_changed_list = "\n".join(f"- `{fp}`" for fp in file_changes.keys())

    pr_body_prompt = ISSUE_SOLVER_PR_BODY_TEMPLATE.format(
        issue_number=issue_number,
        issue_title=issue_title,
        analysis=analysis,
        files_changed=files_changed_list,
    )
    pr_body = call_llm(model, pr_body_prompt)

    try:
        default_branch = repo.default_branch
        pr = repo.create_pull(
            title=f"🤖 [TENET] Fix: {issue_title}",
            body=pr_body,
            head=branch_name,
            base=default_branch,
            draft=False,
        )
        print(f"✅ PR #{pr.number} created: {pr.html_url}")

        try:
            pr.add_to_labels("tenet-agent")
        except GithubException:
            pass  # Label doesn't exist — not a fatal error

    except GithubException as e:
        print(f"❌ Failed to create PR: {e}")
        post_issue_comment(
            repo,
            issue_number,
            f"## 🤖 TENET Agent - PR Creation Failed\n\n"
            f"Branch `{branch_name}` was pushed, but opening the PR failed:\n\n"
            f"```\n{e}\n```\n\n"
            f"Please open a PR from that branch manually.\n\n---\n*TENET Agent 🛡️*",
        )
        sys.exit(1)

    # ── Post success comment on original issue ─────────────────────────────────
    success_comment = (
        f"## 🤖 TENET Agent - Fix Ready for Review\n\n"
        f"I've analyzed issue #{issue_number} and generated an automated fix.\n\n"
        f"**PR**: {pr.html_url}\n"
        f"**Branch**: `{branch_name}`\n\n"
        f"**Files changed:**\n{files_changed_list}\n\n"
        f"Please review the PR and merge if the fix looks correct. "
        f"If changes are needed, you can push additional commits to `{branch_name}`.\n\n"
        f"---\n*TENET Agent 🛡️ | Triggered by @{triggered_by}*"
    )
    post_issue_comment(repo, issue_number, success_comment)
    print("✅ TENET Issue Solver complete.")


if __name__ == "__main__":
    main()
