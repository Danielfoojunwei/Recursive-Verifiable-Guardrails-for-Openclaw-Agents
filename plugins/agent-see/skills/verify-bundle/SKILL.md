---
name: verify-bundle
description: >
  Verify the quality and grounding of an agent bundle. Use when the user asks to
  "verify the bundle", "check conversion quality", "validate the output",
  "run agent-see verify", "check grounding", "audit the conversion",
  or wants to assess whether a converted bundle is truthful and complete.
---

# Verify Agent Bundle

Run the Agent-See verification pipeline to assess conversion quality, grounding fidelity, and completeness of an existing agent bundle.

## Pre-flight

1. Verify `agent-see` is installed (install if missing — see convert-source skill).
2. Confirm a grounded agent bundle exists. Check for `agent_card.json`:
   ```bash
   ls <output-dir>/agent_card.json
   ```
3. Check the `proof/` directory exists and contains grounding evidence:
   ```bash
   ls <output-dir>/proof/
   ```

## Run Verification

```bash
agent-see verify <output-dir> --verbose
```

## Interpret Results

The verification command outputs quality metrics across three dimensions:

### Coverage
Measures what percentage of discovered capabilities were successfully extracted.
- **High (>80%)** — most business actions captured
- **Medium (50-80%)** — significant gaps, consider re-running with broader scope
- **Low (<50%)** — substantial missing functionality, re-run required

### Fidelity
Measures how accurately the extracted capabilities match the source surface.
- **High** — extracted actions faithfully represent the original business logic
- **Medium** — some actions have simplified or approximated parameters
- **Low** — significant deviations from source behavior

### Hallucination Detection
Identifies any generated capabilities that have no grounding evidence.
- **None detected** — all capabilities are backed by proof artifacts
- **Warnings** — some capabilities have weak grounding evidence
- **Critical** — fabricated capabilities found, must be removed before launch

## Report to User

Present a structured verification summary:

1. **Overall quality score** — composite of coverage, fidelity, and hallucination metrics
2. **Coverage gaps** — list workflows that were not captured
3. **Fidelity issues** — list actions where extraction was imprecise
4. **Hallucination flags** — list any fabricated capabilities (critical to address)
5. **Recommendation** — whether to proceed to launch/packaging or re-run conversion

## Remediation

If issues are found:

| Issue type | Remediation |
|-----------|-------------|
| Low coverage | Re-run conversion with adjusted scope or better access |
| Low fidelity | Re-run conversion with verbose mode for more detailed extraction |
| Hallucinations | Remove fabricated entries from skills/ and update agent_card.json |
| Missing proof | Re-run conversion to regenerate grounding evidence |
