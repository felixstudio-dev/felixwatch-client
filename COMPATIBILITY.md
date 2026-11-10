# Compatibility Matrix

No public Felix Watch Client component or version has been qualified. The
following is a *verification inventory*, not a supported-version matrix:

| Consumer/interface | Platform or protocol dimensions to verify | Supported Client versions |
| --- | --- | --- |
| Linux/VPS agent | Architecture, distro, init system, collector, heartbeat, resource footprint | None released |
| PHP shared-hosting probe | PHP/hosting capabilities, transport/auth, scheduled execution | None released |
| API clients/webhooks | API and payload versions, auth, replay/idempotency, backwards compatibility | None released |
| WordPress/framework plugins | Host/framework, PHP/runtime, permissions, upgrade/rollback | None released |

Release documents must add exact tested versions, minimum requirements,
producer/consumer combinations, breaking changes and migration instructions
only after independent, reproducible validation.
