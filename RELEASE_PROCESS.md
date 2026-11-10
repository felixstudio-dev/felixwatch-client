# Governed Release and Rollback

No public release pipeline or tag-based publishing is enabled or claimed.
For each approved component version, maintainers must record source repository,
path and exact commit, platform/contract compatibility, licenses and upstream
provenance, vulnerability/secret review, CI and physical test receipts where
necessary, resource metrics, sanitized target file set, SHA-256 hashes,
version changelog, support/EOL decision and upgrade/rollback documentation.

An independent security/quality and human publication gate reviews the exact
public diff before creation/merge of public artifacts, tags or packages.
After publication, preserve immutable tags and release provenance; fixes use
new versions, with rollback/deprecation/security notices as applicable.
No private-tree auto-sync, unchecked publishing or additional paid services.
