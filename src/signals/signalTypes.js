/**
 * BHEESHMA Signal Type Definitions
 * 
 * Security: Immutable signal schema ensuring integrity and preventing tampering.
 * Follows OWASP principle: "Define security requirements"
 * 
 * Each signal represents a runtime behavior observed from a third-party dependency.
 * Signals are metadata-only and never capture sensitive content (passwords, keys, etc.)
 */

'use strict';

/**
 * Signal Types - Enumeration of observable runtime behaviors
 * @readonly
 * @enum {string}
 */
const SignalType = Object.freeze({
  ENV_ACCESS: 'ENV_ACCESS',       // Access to process.env
  FS_READ: 'FS_READ',             // File system read operation
  FS_WRITE: 'FS_WRITE',           // File system write operation
  SHELL_EXEC: 'SHELL_EXEC',       // Shell/child process execution
  NET_CONNECT: 'NET_CONNECT'      // Outbound network connection
});

/**
 * Create an immutable signal object
 * 
 * Security considerations:
 * - Objects are frozen to prevent tampering
 * - Timestamps use ISO 8601 for deterministic comparison
 * - Stack traces are sanitized (caller responsible for filtering sensitive paths)
 * - Metadata is intentionally limited to prevent secret leakage
 * 
 * @param {string} type - Signal type from SignalType enum
 * @param {object} metadata - Type-specific metadata (varies by signal type)
 * @param {string} packageName - Attributed npm package (or null if first-party)
 * @param {string} packageVersion - Package version
 * @param {string} stackTrace - Sanitized stack trace
 * @returns {object} Frozen signal object
 */
function createSignal(type, metadata, packageName, packageVersion, stackTrace) {
  // Defensive: Validate signal type
  if (!Object.values(SignalType).includes(type)) {
    throw new TypeError(`Invalid signal type: ${type}`);
  }

  const signal = {
    timestamp: new Date().toISOString(),
    type,
    package: packageName || null,
    version: packageVersion || null,
    metadata: metadata || {},
    stackTrace: stackTrace || null
  };

  // Security: Make immutable to prevent post-creation tampering
  return Object.freeze(signal);
}

/**
 * Validate signal metadata based on type
 * Ensures required fields are present for each signal type
 * 
 * @param {string} type - Signal type
 * @param {object} metadata - Metadata to validate
 * @returns {boolean} True if valid
 */
function validateSignalMetadata(type, metadata) {
  if (!metadata || typeof metadata !== 'object') {
    return false;
  }

  switch (type) {
    case SignalType.ENV_ACCESS:
      // Must have variable name (not value - security consideration)
      return typeof metadata.variable === 'string';
    
    case SignalType.FS_READ:
    case SignalType.FS_WRITE:
      // Must have file path (absolute, sanitized)
      return typeof metadata.path === 'string';
    
    case SignalType.SHELL_EXEC:
      // Must have command (sanitized - no interpolated secrets)
      return typeof metadata.command === 'string';
    
    case SignalType.NET_CONNECT:
      // Must have host and port
      return typeof metadata.host === 'string' && 
             typeof metadata.port === 'number';
    
    default:
      return false;
  }
}

module.exports = {
  SignalType,
  createSignal,
  validateSignalMetadata
};
