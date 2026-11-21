# MiroFish Simulation Prompts & Scenario Injection Guide

> **Ready for `666ghj/MiroFish` (`http://localhost:3000`)**: Upload `01_project_seed_dossier.md` and `02_entity_ontology.json` into MiroFish's Step 1 (Graph Building), then inject the scenarios below during Step 2 (Environment Setup) and Step 3 (Simulation Execution).

---

## Scenario 1: Enterprise Fortune 500 RFP & Proof-of-Value (Mode B Fleet)
**Prompt Injection:**
> OmniConnect Sentinel pitches a 50,000-seat Fortune 500 enterprise at \$12/seat/month (\$7.2M/year ARR) to replace USB risk gaps left by Microsoft Defender for Endpoint (E5) and CrowdStrike Falcon. The CISO invites the MDM Admin, Red-Team Lead, Compliance Auditor, Finance/Dev End Users, and an incumbent CrowdStrike/Microsoft account team to tear apart the 90-day pilot proposal. Simulate the technical PoV, incident drills, helpdesk fallout, and final procurement vote. Identify every fatal flaw that kills or stalls the deal.

## Scenario 2: Air-Gapped Critical Infrastructure Substation Deployment (Mode A Kiosk)
**Prompt Injection:**
> An energy utility operating 40 IEC 62443-3-3 SL-3 air-gapped substations evaluates replacing \$60,000 OPSWAT MetaDefender hardware kiosks with OmniConnect Sentinel running on hardened industrial PCs (`sentinel kiosk`). A field vendor arrives with a 12 GB USB drive containing Siemens/Rockwell PLC firmware updates (`.zip`/`.iso`/proprietary signed `.bin`), CAD drawings, and Excel calibration spreadsheets with VBA macros. Simulate what succeeds, what breaks, and where Sentinel's current architecture fails real OT operations.

## Scenario 3: Adversarial Red-Team Break-In Against Ring 3 Invariants
**Prompt Injection:**
> A nation-state/red-team adversary targeting an air-gapped defense contractor knows the target runs OmniConnect Sentinel (Ring 3 userspace, zero custom kernel driver, `MountMgr` auto-mount disable, ProjFS/FUSE ShadowCache, `sentinel-cdr-worker` AppContainer, localhost `127.0.0.1:8088` UI). Simulate 5 distinct physical/logical bypass campaigns (BadUSB HID/RNDIS, MTP smartphone, Thunderbolt/USB4, race conditions, CDR/file-format evasion, and local privilege/UI abuse) and identify which attacks succeed despite invariants I1–I5.

## Scenario 4: Regulatory Audit & Legal Liability Shock
**Prompt Injection:**
> Six months after deployment, two events occur simultaneously: (1) A FedRAMP / IEC 62443 / ISO 27001 external auditor inspects OmniConnect Sentinel's FIPS 186-5, NIST SP 800-88, and TPM/keyring claims; (2) Sentinel's PDF/OpenXML CDR silently strips digital signature validity and embedded macros from a mission-critical supplier contract and SCADA calibration sheet, causing a \$2M operational dispute. Simulate the audit findings and legal/procurement fallout.

## Report Generation Prompt (Step 4 — MiroFish ReportAgent)
> Synthesize all multi-round agent interactions into a brutally honest Flaw Discovery & Viability Forecast Report. Exclude generic praise. Rank every flaw from P0 (Existential / Deal-Killer) to P3 (Friction / Polish), explicitly separate real code-verified architectural gaps from business/GTM flaws, highlight where Mode A (OT Kiosk) vs Mode B (Corporate Fleet) diverge in viability, and prescribe concrete architectural and strategic pivots.
