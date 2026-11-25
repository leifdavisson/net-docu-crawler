<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing to Net-Docu-Crawler

Thank you for contributing to **Net-Docu-Crawler**! We welcome bug fixes, vendor drivers, parser improvements, and documentation updates.

## Licensing Notice

By contributing to this repository, you agree to license your contribution under the **GNU Affero General Public License Version 3.0 or later (`AGPL-3.0-or-later`)**. Include the AGPLv3 header block and `SPDX-License-Identifier: AGPL-3.0-or-later` on all new source and documentation files.

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/net-docu-crawler.git
   cd net-docu-crawler
   ```
2. **Create a Virtual Environment and Install Development Dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
   *(Alternatively, `pip install -r requirements-dev.txt` installs the exact same core and developer tool pins: [pytest](https://docs.pytest.org/), [Ruff](https://docs.astral.sh/ruff/), [pre-commit](https://pre-commit.com/), and [mypy](https://mypy-lang.org/). For optional Cisco IOS-XR NETCONF/gNMI tooling, also install `pip install -e ".[xr]"`.)*
3. **Read the Architecture & Driver Contract**:
   Review [`AGENTS.md`](AGENTS.md) and [`docs/drivers/overview.md`](docs/drivers/overview.md) before modifying drivers or topology logic.

## Development Guidelines

1. **Zero-Blast-Radius Telemetry**: Execute exclusively read-only operational commands (`show`, `get`, `ubus call`, `uci export`, `ifconfig`). Never mutate device state or enter configuration mode.
2. **Quality & Verification**: Run linter and unit tests before opening a Pull Request:
   ```bash
   ruff check .
   pytest -v
   ```

## Contact
Open a GitHub Issue or contact **leifdavisson@gmail.com**.
