# Third-party dependencies and provenance

This file is the Gate 0 dependency register. It must be updated before adding or
upgrading a dependency.

| Component | Purpose | Source | License | Bundled? |
|---|---|---|---|---|
| Rust toolchain | system runtime build | rust-lang.org | Apache-2.0 OR MIT components | no |
| Serde / serde_json | Rust contract serialization | crates.io | Apache-2.0 OR MIT | source dependency |
| Python | fake ASM runtime and tests | python.org | PSF-2.0 | no |
| Linux / Ubuntu | target platform | kernel.org / ubuntu.com | respective upstream licenses | no |
| AppArmor / BPF / LSM | future integration surface | upstream projects | respective upstream licenses | no |

No Linux, Ubuntu, AppArmor, BPF, systemd, or third-party project is relicensed
by Unix-AGB. Commercial licensing can cover only rights the licensor is legally
authorized to license.

Before release, generate and review a dependency lockfile/license report and
record all copied assets, datasets, checkpoints, and external contributions.
