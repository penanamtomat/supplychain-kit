### Product Requirements Document (PRD): Integrated Application Security Posture Management (ASPM) Platform

#### 1\. Executive Vision and Strategic Context

As we navigate the 2026 security landscape, the traditional perimeter has dissolved, replaced by a complex, high-velocity software supply chain. The industry has reached a strategic inflection point, evolving from reactive Application Security Orchestration and Correlation (ASOC) to proactive Application Security Posture Management (ASPM). This shift is necessitated by the "perfect storm" of AI-accelerated code production and a 742% annual increase in supply chain attacks. With modern applications relying on third-party dependencies for 70% to 90% of their codebase, the gap between first-party code logic and third-party component integrity represents our greatest systemic risk.The core problem is no longer a lack of data, but "alert fatigue" caused by siloed tools. This ASPM platform transforms security from a developmental "blocker" to a business "enabler" by correlating Static Application Security Testing (SAST) and Software Composition Analysis (SCA) findings. By implementing reachability analysis—verifying if a vulnerable library is actually executed in the runtime path—and deploying AI-powered remediation, we aim to eliminate the noise of non-exploitable vulnerabilities. This document serves as the technical blueprint for a system that ensures security scales at the speed of AI-driven development.

#### 2\. Product Objectives and Key Personas

The primary objective is to provide a unified risk management framework that consolidates findings from disparate scanners into a single, actionable pane of glass.

| Broad Strategic Goal | Tactical Outcome (KPI) |
| ----- | ----- |
| **Eliminate Operational Noise** | Target a  **90% reduction**  in non-reachable dependency alerts via call-graph and eBPF correlation. |
| **Accelerate Remediation** | Achieve an  **87.5% reduction**  in Mean Time to Remediation (MTTR) through AI-powered automated PR generation. |
| **Continuous Visibility** | Maintain a 100% real-time inventory of assets across hybrid/multi-cloud environments using SBOM-first workflows. |
|  **Agentic Integrity** | Implement "Agentic SAST" to secure AI-generated code snippets at the moment of creation. |

##### User Personas

* **AppSec Engineer (Triage and Policy):**  Requires a centralized platform to normalize findings across 200+ integrations. Focuses on defining "Quality Gates" and managing the transition from manual triage to automated ASPM workflows.  
* **Software Developer (Remediation and IDE Feedback):**  Needs immediate, low-noise feedback. Their goal is "Fix-First" security, utilizing AI-powered remediation directly within their IDE and Pull Request (PR) cycles to avoid context switching.  
* **CISO (Compliance and Risk Dashboards):**  Focuses on high-level security posture and regulatory alignment (NIST, SLSA). Requires machine-readable VEX reporting to communicate risk status to external stakeholders and auditors.

#### 3\. Functional Requirements: Integrated Scanning & Orchestration

The system must transform raw telemetry into a prioritized risk model, focusing on the exploitability of the full stack.

##### 3.1 SCA & SBOM Management

The system shall utilize  **Syft**  to generate comprehensive Software Bills of Materials (SBOM) in CycloneDX 1.5 format. These SBOMs will be continuously monitored by  **Dependency-Track** , allowing for "scan-once, monitor-always" logic. This ensures that when a new CVE (e.g., Log4Shell) is disclosed, the platform identifies affected projects immediately without a full CI re-scan.

##### 3.2 SAST & Agentic Security

The platform must support deep code analysis using  **Semgrep**  for rapid pattern matching and  **Joern**  for complex structural analysis.

* **Agentic SAST:**  To address AI-accelerated development, the system must integrate with AI coding assistants (e.g., GitHub Copilot, Claude Code) to flag vulnerabilities in AI-generated code  *before*  commit.  
* **Secret Scanning:**   **Gitleaks**  shall be integrated as the mandatory standard to prevent credential leakage in git history.

##### 3.3 The "Reachability" Engine

The system must correlate SAST call graphs with SCA findings to distinguish between "Known Affected" and "Not Affected" components.

* **Technical Logic:**  The engine will leverage Joern's  **Code Property Graph (CPG)**  to map execution paths from first-party "sources" to third-party "sinks."  
* **Runtime Context:**  To bolster accuracy, the system shall ingest  **eBPF sensor data**  to verify which libraries are actually loaded into memory at runtime, providing the ultimate ground truth for reachability.

##### 3.4 Automated Remediation

The system shall automate the fix lifecycle by:

* Integrating with  **Mend Renovate**  logic to auto-generate PRs that upgrade dependencies to the nearest compatible non-vulnerable version.  
* Utilizing LLM-driven "Remediation Agents" to suggest code refactors for proprietary SAST findings.  
* Validating fixes through automated re-scanning to confirm vulnerability closure.

#### 4\. Technical Architecture and Stack

The ASPM platform is built on a modular, high-concurrency architecture designed for large-scale enterprise environments.

##### 4.1 Core Tech Stack

| Component | Technology | Rationale |
| ----- | ----- | ----- |
| Core Engine | Go | High-performance concurrency for massive AST/CPG parsing. |
| Remediation Layer | Python | Extensive library support for security playbooks and AI orchestration. |
| Vulnerability Matcher | Grype | SBOM-first scanning ; matches Syft JSON/CycloneDX to save CI compute cycles. |
| SAST/Patterning | Semgrep | Developer-friendly YAML rules with 38% better precision in 2026 benchmarks. |
| Normalization | DefectDojo | Standardized ASOC layer for de-duplicating and normalizing findings from 200+ sources. |
| Data Layer | PostgreSQL | Centralized storage for CPG metadata and asset risk history. |

##### 4.2 System Architecture Description

* **Ingestion Layer:**  Connects via bi-directional APIs to GitHub, GitLab, and Bitbucket. It monitors for commits, manifest changes, and PR events.  
* **Analysis Layer (Normalization):**  Findings are ingested into  **DefectDojo** . The system performs de-duplication (e.g., merging a SAST finding and a DAST finding that point to the same root cause) and normalizes the data into a common schema.  
* **Correlation & Scoring Engine:**  Applies the  **Integrated Risk Score**  formula:  $$\\text{Risk Score} \= \\text{Severity (CVSS)} \\times \\text{Reachability} \\times \\text{Exposure} \\times \\text{Criticality}$$   *Reachability*  is a binary multiplier (0.1 if unreachable, 1.0 if reachable/eBPF confirmed).  *Exposure*  factors in internet-facing status.

#### 5\. Development Roadmap: A Four-Phase Evolution

1. **Phase 1: Visibility (Months 1-3):**  Deploy Syft/Grype for SBOM generation. Establish the "Single Pane of Glass" in DefectDojo. Implement Gitleaks for secret scanning.  
2. **Phase 2: Orchestration & Reachability PoC (Months 4-6):**  Integrate CI/CD Quality Gates. Launch Proof of Concept for Joern-based reachability to validate the Risk Scoring logic.  
3. **Phase 3: Intelligence (Months 7-10):**  Full deployment of Reachability Analysis using CPG and eBPF runtime context. Implement "Agentic SAST" for real-time AI code verification.  
4. **Phase 4: Automation (Months 11-15):**  AI-powered remediation agents integrated with GitHub/GitLab PRs. Automated generation of CSAF 2.0 VEX reports.

#### 6\. Compliance, Standards, and Reporting

The platform satisfies international frameworks through automated metadata provenance and audit-ready outputs.

* **NIST SSDF (SP 800-218):**  Aligns with the "Protect the Software" (PS) group by verifying release integrity and tracking the provenance of all components.  
* **SLSA (L1-L3):**  Ensures build-time integrity, providing technical assurance that artifacts originate from trusted source code.  
* **OWASP SCVS:**  Manages technical debt by identifying outdated components and quantifying vendor risk.  
* **VEX Reporting:**  Generates  **CSAF 2.0 (Profile 5\)**  reports. The system must support standard  **CISA Status Justifications** , specifically:  
* vulnerable\_code\_not\_present (Unreachable via CPG analysis).  
* inline\_mitigation\_already\_exist (e.g., WAF or compensating control).  
* vulnerable\_code\_cannot\_be\_controlled\_by\_adversary.

#### 7\. Implementation Limitations and Guardrails

* **Analysis Trade-offs:**  While reachability analysis targets a 90% noise reduction, complex dynamic languages (e.g., JavaScript/Python) may produce false negatives where execution paths are determined at runtime.  
* **Resource Requirements:**  On-premises deployment requires significant infrastructure for the CPG/Joern analysis layer. SaaS is recommended for high-velocity teams.  
* **Operational Guardrails:**  Automated PRs for "Critical" infrastructure components must require a "Security Champion" approval before merging. Remediation agents are "Human-in-the-Loop" by default for production-critical branches.This PRD serves as the foundational coding blueprint, moving the organization from fragmented scanning to a cohesive, risk-aware ASPM posture.

