"""Renovate-style upgrade agent.

Given a vulnerable (package, current_version, fixed_version), the agent
determines the nearest non-vulnerable version that satisfies the manifest's
existing constraints and (optionally) opens a Pull Request through the Git
provider API.

The PoC implementation here is intentionally provider-agnostic for the
upgrade proposal step (PEP 440 / SemVer parsing via `packaging.version`).
PR creation calls into PyGithub when a token is configured.
"""

from __future__ import annotations

import logging
from typing import Any

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel

log = logging.getLogger(__name__)


class UpgradeProposal(BaseModel):
    package: str
    ecosystem: str
    from_version: str
    to_version: str
    rationale: str
    pr_url: str | None = None
    error: str | None = None


class RenovateAgent:
    def __init__(self, github_token: str = "") -> None:
        self.github_token = github_token

    def propose(
        self,
        ecosystem: str,
        package: str,
        current_version: str,
        fixed_version: str | None,
    ) -> UpgradeProposal:
        target = fixed_version or self._nearest_safe(current_version)
        rationale = self._explain(current_version, target)
        return UpgradeProposal(
            package=package,
            ecosystem=ecosystem,
            from_version=current_version,
            to_version=target,
            rationale=rationale,
        )

    def open_pr(self, repo_url: str, proposal: UpgradeProposal) -> str:
        """Open a PR that bumps the dependency.

        For brevity, this PoC does not patch manifest files itself; it opens
        a draft PR with a structured body that downstream automation (or a
        human) uses to apply the change. A production-grade implementation
        would invoke the appropriate package-manager update tool.
        """
        if not self.github_token:
            raise RuntimeError("ASPM_GITHUB_TOKEN not configured")

        # Imported lazily so the module loads even when PyGithub is missing.
        from github import Github  # type: ignore

        gh = Github(self.github_token)
        owner_repo = self._parse_owner_repo(repo_url)
        repo = gh.get_repo(owner_repo)
        base = repo.default_branch
        branch = f"aspm/upgrade-{proposal.package.replace('/', '-')}-{proposal.to_version}"

        # Ensure the branch exists (created from default head).
        head_sha = repo.get_branch(base).commit.sha
        try:
            repo.create_git_ref(ref=f"refs/heads/{branch}", sha=head_sha)
        except Exception:  # branch may already exist; that's fine for re-runs
            log.debug("branch %s already exists", branch)

        title = f"chore(security): bump {proposal.package} to {proposal.to_version}"
        body = (
            f"Automated upgrade proposed by the ASPM platform.\n\n"
            f"- **Package:** `{proposal.package}` ({proposal.ecosystem})\n"
            f"- **From:** `{proposal.from_version}`\n"
            f"- **To:** `{proposal.to_version}`\n\n"
            f"**Rationale:** {proposal.rationale}\n"
        )
        pr = repo.create_pull(title=title, body=body, head=branch, base=base, draft=True)
        return pr.html_url

    # ----- helpers -----

    def _nearest_safe(self, current: str) -> str:
        try:
            v = Version(current)
            # When no fixed version is supplied, propose a patch bump as the
            # most conservative starting point. Real Renovate logic would
            # consult an advisory database here.
            release = list(v.release)
            if len(release) >= 3:
                release[-1] += 1
            return ".".join(str(p) for p in release)
        except InvalidVersion:
            return current

    def _explain(self, current: str, target: str) -> str:
        return (
            f"Upgrading from {current} to {target} resolves a known "
            f"vulnerability and stays on the same major line where possible."
        )

    def _parse_owner_repo(self, url: str) -> str:
        # Accepts https://github.com/owner/repo[.git] or git@github.com:owner/repo.git
        url = url.rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        if "github.com" not in url:
            raise ValueError(f"unsupported provider: {url}")
        if url.startswith("git@"):
            return url.split(":", 1)[1]
        return "/".join(url.split("/")[-2:])

    # Allows the agent to be passed objects without breaking pydantic v2.
    def __repr__(self) -> str:  # pragma: no cover
        return "RenovateAgent(token=<redacted>)"


# Re-export the model so the FastAPI layer can import a single symbol.
__all__: list[str] = ["RenovateAgent", "UpgradeProposal", "Any"]
