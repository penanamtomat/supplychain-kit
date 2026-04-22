"""CSAF 2.0 (Profile 5) VEX document generator.

Implements the subset of CSAF 2.0 needed to publish a Vulnerability
Exploitability eXchange document for a release. The supported status
justifications match the PRD requirement for CISA-aligned outputs:

  - vulnerable_code_not_present
  - inline_mitigation_already_exist
  - vulnerable_code_cannot_be_controlled_by_adversary
  - vulnerable_code_not_in_execute_path
"""

from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, Field

VEXStatus = Literal["affected", "not_affected", "fixed", "under_investigation"]

VEXJustification = Literal[
    "vulnerable_code_not_present",
    "inline_mitigation_already_exist",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "vulnerable_code_not_in_execute_path",
]


class VEXFinding(BaseModel):
    cve: str
    status: VEXStatus
    justification: VEXJustification | None = None
    impact_statement: str | None = None
    remediation: str | None = None


class VEXGenerator:
    def __init__(self, publisher: str) -> None:
        self.publisher = publisher

    def generate(
        self,
        document_id: str,
        product_name: str,
        product_version: str,
        findings: list[VEXFinding],
    ) -> dict:
        self._validate(findings)
        product_id = f"{product_name}@{product_version}".lower()
        return {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "publisher": {"category": "vendor", "name": self.publisher},
                "title": f"VEX for {product_name} {product_version}",
                "tracking": {
                    "id": document_id,
                    "status": "final",
                    "version": "1",
                    "initial_release_date": _now_iso(),
                    "current_release_date": _now_iso(),
                    "revision_history": [
                        {"date": _now_iso(), "number": "1", "summary": "Initial release."}
                    ],
                },
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "product_name",
                        "name": product_name,
                        "branches": [
                            {
                                "category": "product_version",
                                "name": product_version,
                                "product": {
                                    "name": product_name,
                                    "product_id": product_id,
                                },
                            }
                        ],
                    }
                ]
            },
            "vulnerabilities": [self._vuln(product_id, f) for f in findings],
        }

    def _vuln(self, product_id: str, f: VEXFinding) -> dict:
        entry: dict = {"cve": f.cve, "product_status": {self._status_key(f.status): [product_id]}}
        if f.status == "not_affected":
            if not f.justification:
                raise ValueError(f"{f.cve}: justification required when status=not_affected")
            entry["flags"] = [
                {
                    "label": f.justification,
                    "product_ids": [product_id],
                }
            ]
            if f.impact_statement:
                entry["impact"] = f.impact_statement
        if f.remediation:
            entry["remediations"] = [
                {
                    "category": "vendor_fix",
                    "details": f.remediation,
                    "product_ids": [product_id],
                }
            ]
        return entry

    @staticmethod
    def _status_key(status: VEXStatus) -> str:
        return {
            "affected": "known_affected",
            "not_affected": "known_not_affected",
            "fixed": "fixed",
            "under_investigation": "under_investigation",
        }[status]

    @staticmethod
    def _validate(findings: list[VEXFinding]) -> None:
        if not findings:
            raise ValueError("at least one finding required")


def _now_iso() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Re-export so the API layer can import a single symbol.
class VEXSummary(BaseModel):
    document_id: str
    findings: list[VEXFinding] = Field(default_factory=list)
