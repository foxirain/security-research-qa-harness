# Publication Safety

This repository contains only synthetic cases and generalized methodology. Do not copy an internal QA session into a public branch without a separate disclosure review.

## Exclude by default

- unpublished vulnerability details or reproduction inputs;
- vendor-private reports, comments, patches, and timelines;
- tokens, cookies, authorization headers, account identifiers, and production URLs;
- customer, tenant, employee, or device data;
- core dumps, heap dumps, database snapshots, and raw packet captures;
- exploit chains or post-compromise material whose primary value is weaponization;
- artifacts whose third-party license or disclosure permission is unclear.

## Required review before publication

1. Confirm that the vulnerability and the specific technical detail are already public or explicitly approved for release.
2. Re-run the case with disposable credentials and synthetic data.
3. Inspect every collected artifact, not only generated Markdown.
4. Search the complete tree and Git history for credentials, private paths, email addresses, and vendor-private identifiers.
5. Keep only the minimum evidence needed to explain the QA method.
6. State provenance and non-claims precisely. A retrospective reconstruction must be labeled as retrospective.

## Built-in protection and its limit

The executor redacts configured bearer tokens, cookies, and header values from stored commands and text logs. `analysis.json` also stores redacted authentication fields. This does not inspect arbitrary binary artifacts or discover credentials that were never declared in the case configuration. Publication review remains mandatory.
