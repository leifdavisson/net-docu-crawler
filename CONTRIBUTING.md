# Contributing to Net-Docu-Crawler

Thank you for contributing to **Net-Docu-Crawler**! We welcome bug fixes, vendor drivers, parser improvements, and documentation updates.

## Licensing Notice

By contributing to this repository, you agree to license your contribution under the **GNU Affero General Public License Version 3.0 or later (`AGPL-3.0-or-later`)**. Include the AGPLv3 header block on all new source files.

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/net-docu-crawler.git
   cd net-docu-crawler
   ```
2. **Install Development Dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```
3. **Read the Architecture & Driver Contract**:
   Review [`AGENTS.md`](AGENTS.md) and [`docs/drivers/overview.md`](docs/drivers/overview.md) before modifying drivers or topology logic.

## Development Guidelines

1. **Zero-Blast-Radius Telemetry**: Execute exclusively read-only operational commands (`show`, `get`, `ubus call`, `uci export`, `ifconfig`). Never mutate device state.
2. **Quality & Verification**: Run linter and unit tests before opening a Pull Request:
   ```bash
   ruff check .
   pytest -v
   ```

## Contact
Open a GitHub Issue or contact **leifdavisson@gmail.com**.
