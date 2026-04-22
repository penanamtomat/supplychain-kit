"""FastAPI surface for the remediation service.

Endpoints:
  - POST /remediate/sca   – propose a Renovate-style upgrade PR
  - POST /remediate/sast  – propose an LLM-authored code fix
  - POST /vex             – generate a CSAF 2.0 (Profile 5) VEX document
  - GET  /health
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from remediation.agents.llm_agent import LLMRemediationAgent
from remediation.agents.renovate_agent import RenovateAgent, UpgradeProposal
from remediation.reports.vex_generator import VEXGenerator, VEXFinding

log = logging.getLogger("aspm.remediation")
logging.basicConfig(level=os.environ.get("ASPM_LOG_LEVEL", "INFO"))

app = FastAPI(title="ASPM Remediation Service", version="0.1.0")


# ---------- Schemas ----------


class SCARemediateRequest(BaseModel):
    package: str
    ecosystem: str = Field(description="npm / pypi / maven / go / cargo / ...")
    current_version: str
    fixed_version: str | None = None
    repo_url: str | None = None
    open_pr: bool = False


class SASTRemediateRequest(BaseModel):
    rule_id: str
    file_path: str
    line: int
    snippet: str
    rule_description: str = ""


class VEXRequest(BaseModel):
    document_id: str
    publisher: str = "aspm-platform"
    product_name: str
    product_version: str
    findings: list[VEXFinding]


# ---------- Endpoints ----------


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/remediate/sca")
def remediate_sca(req: SCARemediateRequest) -> UpgradeProposal:
    agent = RenovateAgent(github_token=os.environ.get("ASPM_GITHUB_TOKEN", ""))
    proposal = agent.propose(
        ecosystem=req.ecosystem,
        package=req.package,
        current_version=req.current_version,
        fixed_version=req.fixed_version,
    )
    if req.open_pr and req.repo_url:
        try:
            proposal.pr_url = agent.open_pr(req.repo_url, proposal)
        except Exception as e:  # pragma: no cover - depends on external API
            log.warning("PR creation failed: %s", e)
            proposal.error = str(e)
    return proposal


@app.post("/remediate/sast")
def remediate_sast(req: SASTRemediateRequest) -> dict[str, Any]:
    agent = LLMRemediationAgent(
        provider=os.environ.get("ASPM_LLM_PROVIDER", "anthropic"),
        api_key=os.environ.get("ASPM_LLM_API_KEY", ""),
    )
    suggestion = agent.suggest_fix(
        rule_id=req.rule_id,
        file_path=req.file_path,
        line=req.line,
        snippet=req.snippet,
        rule_description=req.rule_description,
    )
    return suggestion.model_dump()


@app.post("/vex")
def generate_vex(req: VEXRequest) -> dict[str, Any]:
    gen = VEXGenerator(publisher=req.publisher)
    try:
        doc = gen.generate(
            document_id=req.document_id,
            product_name=req.product_name,
            product_version=req.product_version,
            findings=req.findings,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return doc
