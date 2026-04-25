---
name: False positive / false negative
about: A finding that shouldn't be there, or a vulnerability that was missed
title: "[FP/FN] "
labels: triage
assignees: ''
---

**Finding type**
- [ ] False positive (finding reported but not a real issue)
- [ ] False negative (real vulnerability not detected)

**Scanner involved**
- [ ] grype (SCA)
- [ ] trivy (SCA)
- [ ] osv-scanner (SCA)
- [ ] semgrep (SAST)
- [ ] gitleaks (secrets)
- [ ] taint engine (reachability)

**Finding details**
```
# Paste the finding JSON or table output here
```

**Why it's incorrect**
Explain why this is a false positive or false negative.

**supplychain-kit version**: (`supplychain-kit --version`)
