# Changelog

All notable changes to BHEESHMA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-18

### Added
- **Runtime Behavior Monitoring**
  - Environment variable access detection (ENV_ACCESS)
  - Filesystem read/write monitoring (FS_READ, FS_WRITE)
  - Network connection detection (NET_CONNECT)
  - Shell execution monitoring (SHELL_EXEC)

- **Attribution Engine**
  - Stack trace analysis for package identification
  - Support for scoped packages (@scope/package)
  - Package.json version resolution
  - Caching for performance

- **Trust Scoring System**
  - Deterministic scoring algorithm (0-100 scale)
  - Risk categorization (LOW, MEDIUM, HIGH, CRITICAL)
  - Transparent risk weights
  - Per-package statistics

- **Output Formats**
  - CLI formatter with color-coded output
  - JSON formatter with schema versioning (v1.0)
  - File output support
  - Risk-based sorting

- **CLI Tool**
  - Executable via `npx bheeshma`
  - Argument parsing (--format, --output)
  - Exit handlers for report generation
  - Error reporting

- **Security Features**
  - Zero telemetry guarantee
  - Metadata-only capture (no secrets)
  - Command sanitization for shell hooks
  - Fail-safe error handling
  - Reversible hooks

- **Testing**
  - 17 automated tests (100% pass rate)
  - Benign dependency simulation
  - Suspicious dependency simulation  
  - Real-world attack scenarios
  - Offline execution

- **Documentation**
  - Comprehensive README (12KB)
  - Inline security comments
  - API documentation
  - Usage examples
  - Apache 2.0 license

### Technical Details
- **Lines of Code**: ~2,130
- **Dependencies**: Zero (core runtime)
- **Node.js Support**: >= 12.0.0
- **Test Coverage**: Complete

### Known Limitations
- ESM support is partial (full support planned for V2)
- Worker threads not monitored (planned for V2)
- Native addons not monitorable (Node.js limitation)

---

## [Unreleased]

### Planned for V2
- Full ESM module support
- Worker thread monitoring
- DNS query detection
- Crypto operation monitoring
- Configurable risk weights
- Policy enforcement mode
- CI/CD integration plugins

---

## Version History

- **1.0.0** (2026-01-18) - Initial public release

---

**Note**: This project was built using AI-assisted "vibe coding" paired with strict engineering discipline. Every component follows OWASP, CERT/SEI, and Node.js security best practices.
