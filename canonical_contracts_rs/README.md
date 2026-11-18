# NewGen Canonical Contracts

Single-source Rust contract modules shared across ecosystems.

Current modules:
- `ai_e2_gateway_v1`: AI↔E2 gateway wire contracts
- `compute_surface_v1`: chain↔E2 compute memo/event/order contracts
- `cognitive_registry_surface_v1`: chain↔AI cognitive registry/finality/anchor wire contracts

Usage model:
- AI and data center depend on this crate directly.
- Chain includes the same module files directly from `src/` to avoid duplicated contract drift.
