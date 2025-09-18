---
name: Patch reward program - secret scanning
about: Submit a secret extractor suggestion for the PRP
title: 'PRP: Secret extractor for {Secret name}'
labels: ['PRP', 'PRP:Request']
assignees: ''

---

- **Secret name**: {e.g. `GCP Service Account Keys`}
- **Risk in exposing the secret**: {e.g. `Attackers can impersonate GCP Service Accounts and get access to Cloud resources`}
- **Validation method, if any**:
 * {APIs queried to verify the secret is associated with a real prod account}
 * {We reward more for secret extractor submissions that also include an
   associated validation Enricher plugin}
- **Resources**:
  * {Any links}
  * {That can be useful to understand more about the secret and how it's used}
