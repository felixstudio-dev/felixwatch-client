# Versioning and Backward Compatibility

No Client distribution has an assigned public release version. When an
individual component is accepted for distribution, use Semantic Versioning
2.0.0 where appropriate: MAJOR for breaking changes, MINOR for backwards-
compatible features, PATCH for backwards-compatible fixes, and labeled
pre-releases when needed. Ecosystem-specific conventions require an approved,
documented exception.

Artifact/package, collector/API, heartbeat protocol, payload/schema,
configuration and installer versions may advance independently. A compatible
artifact name does not prove compatibility: supported producer/consumer
combinations require tests and published evidence. Unknown contract versions
fail conservatively, and security boundaries fail closed.

Public tags, once issued, are immutable. Changes after publication use new
versions and the release review, with migrations/deprecations documented.
