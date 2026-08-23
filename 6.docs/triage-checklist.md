# Triage Checklist

- [ ] What triggered the alert?
- [ ] Which user, host, or asset is involved?
- [ ] Is the behaviour authorized or expected?
- [ ] Are there signs of obfuscation or defense evasion?
- [ ] Are there anomalous network connections?
- [ ] Is there evidence of privilege escalation?
- [ ] Is there lateral movement?
- [ ] Is there persistence established?

### Verdict / Final Disposition
- [ ] **True Positive (Malicious)**: Confirmed security incident.
- [ ] **Benign Positive (Authorized / Tuning required)**: Legitimate action triggered alert.
- [ ] **False Positive**: Erroneous alert or telemetry noise.
- [ ] **Inconclusive**: Insufficient telemetry / pending escalation.