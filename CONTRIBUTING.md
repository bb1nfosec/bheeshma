# Contributing to BHEESHMA

Thank you for your interest in contributing to BHEESHMA! This project aims to provide production-grade runtime security monitoring for Node.js applications.

## Code of Conduct

By participating in this project, you agree to maintain a respectful, professional environment focused on improving supply-chain security.

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating a new issue
3. **Include**:
   - Node.js version
   - BHEESHMA version
   - Minimal reproduction steps
   - Expected vs actual behavior
   - Relevant logs/output

### Suggesting Features

1. **Check roadmap** in README to see if it's planned
2. **Use the feature request template**
3. **Explain**:
   - Use case and problem it solves
   - Proposed solution
   - Alternatives considered
   - Impact on security/performance

### Submitting Code

#### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/bheeshma.git
cd bheeshma

# Install dependencies (none for core runtime, but needed for development)
npm install

# Run tests
npm test
```

#### Making Changes

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Follow coding standards**:
   - Use `'use strict';`
   - Add JSDoc comments for functions
   - Include security rationale in comments
   - Write defensive code (null checks, try-catch)
   - No external dependencies in core runtime

4. **Write tests** for new features
5. **Ensure all tests pass**: `npm test`

#### Coding Standards

**Security-First Principles**:
- Follow OWASP Secure Coding Practices
- Apply CERT/SEI guidelines
- Maintain fail-safe defaults
- Never capture secrets (only metadata)
- Preserve original API behavior

**Code Style**:
- Indentation: 2 spaces
- Line length: <100 characters recommended
- Comments: Explain *why*, not *what*
- Naming: Descriptive, camelCase for variables/functions

**Example**:

```javascript
/**
 * Hook a filesystem function
 * 
 * Security: Non-invasive wrapper preserving original behavior
 * 
 * @param {string} fnName - Function name on fs module
 * @param {string} signalType - FS_READ or FS_WRITE
 * @returns {void}
 */
function hookFunction(fnName, signalType) {
  try {
    // Store original
    originalFunctions[fnName] = fs[fnName];

    // Create wrapper...
  } catch (err) {
    // Fail-safe: Never throw from hooks
  }
}
```

#### Pull Requests

1. **Update documentation** if needed
2. **Add tests** for new behavior
3. **Run full test suite**: `npm test`
4. **Commit with clear messages**:
   ```
   feat: Add DNS query monitoring hook
   
   - Implements dns.resolve* function wrapping
   - Captures query type and hostname
   - Adds 15 new tests
   - Updates README with DNS signals
   ```
5. **Push to your fork**
6. **Create PR** with:
   - Clear description of changes
   - Linked issue (if applicable)
   - Screenshots/examples if relevant
   - Test results

### Review Process

1. **Automated checks** must pass (tests, linting)
2. **Maintainer review** for:
   - Security implications
   - Performance impact
   - Code quality
   - Test coverage
3. **Feedback addressed**
4. **Approval and merge**

## Project Structure

```
bheeshma/
├── bin/          # CLI entry point
├── src/
│   ├── hooks/    # Runtime instrumentation
│   ├── attribution/  # Package resolution
│   ├── signals/  # Signal definitions
│   ├── scoring/  # Trust scoring
│   ├── output/   # Formatters
│   └── index.js  # Main API
└── test/         # Test harness
```

## Security Considerations

### What Should Be Reviewed Carefully

- Hooks that interact with Node.js internals
- Attribution logic (stack trace parsing)
- Signal metadata (ensure no secrets captured)
- Trust scoring weights
- Error handling paths

### What We Won't Merge

- Features with telemetry or external communication
- Code that modifies application behavior
- Opaque ML/AI-based scoring
- Dependencies that increase attack surface
- Code without tests

## Testing Requirements

All contributions must:
- ✅ Pass existing test suite (17/17)
- ✅ Include tests for new features
- ✅ Maintain offline execution
- ✅ Be deterministic (same input = same output)

Run tests:
```bash
npm test
```

## Documentation Requirements

- Update README if user-facing
- Add JSDoc for new functions
- Include inline comments explaining security rationale
- Update CHANGELOG.md

## Questions?

- **Issues**: Use GitHub Issues for bugs/features
- **Security**: See SECURITY.md for vulnerability reporting
- **General**: Open a Discussion on GitHub

## Recognition

Contributors will be:
- Listed in CHANGELOG
- Acknowledged in release notes
- Added to contributors list (if significant contribution)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for helping make Node.js supply chains more secure! 🛡️
