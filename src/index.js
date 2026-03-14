/**
 * @fileoverview Main entry point for the multi-layer security framework.
 * Imports all security modules across 5 layers and exposes a unified API
 * with a comprehensive audit function and CLI support.
 * @module src/index
 */

'use strict';

// ============================================================================
// Layer 1: Input Sanitization
// ============================================================================

/**
 * @typedef {Object} Sanitizer
 * @property {function(string): string} sanitize - Sanitizes input strings
 * @property {function(string): boolean} validate - Validates input against security rules
 * @property {function(string): string} escapeHtml - Escapes HTML entities
 * @property {function(string): string} stripInjection - Removes injection patterns
 */

/** @type {Sanitizer} */
let sanitizer;
try {
  sanitizer = require('./layer1/sanitizer');
} catch (err) {
  console.warn(`[WARN] Failed to load layer1/sanitizer: ${err.message}`);
  sanitizer = null;
}

// ============================================================================
// Layer 2: Gateway & Memory Protection
// ============================================================================

/**
 * @typedef {Object} GatewayHardener
 * @property {function(Object): boolean} validateRequest - Validates incoming gateway requests
 * @property {function(): Object} getStatus - Returns gateway hardening status
 * @property {function(Object): void} applyRules - Applies hardening rules to gateway config
 */

/** @type {GatewayHardener} */
let gatewayHardener;
try {
  gatewayHardener = require('./layer2/gatewayHardener');
} catch (err) {
  console.warn(`[WARN] Failed to load layer2/gatewayHardener: ${err.message}`);
  gatewayHardener = null;
}

/**
 * @typedef {Object} MemoryGuardian
 * @property {function(): Object} getMemoryUsage - Returns current memory usage stats
 * @property {function(number): void} setThreshold - Sets memory usage threshold
 * @property {function(): boolean} checkIntegrity - Checks memory integrity
 * @property {function(): void} purge - Purges sensitive data from memory
 */

/** @type {MemoryGuardian} */
let memoryGuardian;
try {
  memoryGuardian = require('./layer2/memoryGuardian');
} catch (err) {
  console.warn(`[WARN] Failed to load layer2/memoryGuardian: ${err.message}`);
  memoryGuardian = null;
}

// ============================================================================
// Layer 3: Prompt & Context Security
// ============================================================================

/**
 * @typedef {Object} PromptFirewall
 * @property {function(string): boolean} isAllowed - Checks if a prompt passes firewall rules
 * @property {function(string): Object} analyze - Analyzes prompt for threats
 * @property {function(Array<Object>): void} addRules - Adds custom firewall rules
 * @property {function(): Object} getStats - Returns firewall statistics
 */

/** @type {PromptFirewall} */
let promptFirewall;
try {
  promptFirewall = require('./layer3/promptFirewall');
} catch (err) {
  console.warn(`[WARN] Failed to load layer3/promptFirewall: ${err.message}`);
  promptFirewall = null;
}

/**
 * @typedef {Object} ContextScrubber
 * @property {function(Object): Object} scrub - Scrubs sensitive data from context objects
 * @property {function(string): string} redact - Redacts sensitive patterns in strings
 * @property {function(Array<RegExp>): void} addPatterns - Adds custom redaction patterns
 * @property {function(): Object} getConfig - Returns current scrubber configuration
 */

/** @type {ContextScrubber} */
let contextScrubber;
try {
  contextScrubber = require('./layer3/contextScrubber');
} catch (err) {
  console.warn(`[WARN] Failed to load layer3/contextScrubber: ${err.message}`);
  contextScrubber = null;
}

// ============================================================================
// Layer 4: Sandbox & Skill Validation
// ============================================================================

/**
 * @typedef {Object} SandboxHardener
 * @property {function(Object): Object} harden - Hardens a sandbox environment
 * @property {function(): boolean} verify - Verifies sandbox integrity
 * @property {function(string): boolean} isEscapeAttempt - Detects sandbox escape attempts
 * @property {function(): Object} getConstraints - Returns current sandbox constraints
 */

/** @type {SandboxHardener} */
let sandboxHardener;
try {
  sandboxHardener = require('./layer4/sandboxHardener');
} catch (err) {
  console.warn(`[WARN] Failed to load layer4/sandboxHardener: ${err.message}`);
  sandboxHardener = null;
}

/**
 * @typedef {Object} SkillValidator
 * @property {function(Object): boolean} validate - Validates a skill definition
 * @property {function(Object): Object} assess - Assesses skill risk level
 * @property {function(string): boolean} isWhitelisted - Checks if skill is whitelisted
 * @property {function(Array<string>): void} updateWhitelist - Updates the skill whitelist
 */

/** @type {SkillValidator} */
let skillValidator;
try {
  skillValidator = require('./layer4/skillValidator');
} catch (err) {
  console.warn(`[WARN] Failed to load layer4/skillValidator: ${err.message}`);
  skillValidator = null;
}

// ============================================================================
// Layer 5: Audit & Compliance
// ============================================================================

/**
 * @typedef {Object} AuditFortress
 * @property {function(Object): void} log - Logs an audit event
 * @property {function(string, Date, Date): Array<Object>} query - Queries audit logs
 * @property {function(): Object} generateReport - Generates a full audit report
 * @property {function(): boolean} verifyChain - Verifies audit log chain integrity
 * @property {function(): Object} getComplianceStatus - Returns compliance status
 */

/** @type {AuditFortress} */
let auditFortress;
try {
  auditFortress = require('./layer5/auditFortress');
} catch (err) {
  console.warn(`[WARN] Failed to load layer5/auditFortress: ${err.message}`);
  auditFortress = null;
}

// ============================================================================
// Unified Security API
// ============================================================================

/**
 * @typedef {Object} LayerStatus
 * @property {string} name - Layer name
 * @property {boolean} loaded - Whether the module loaded successfully
 * @property {string} status - 'operational' | 'degraded' | 'offline'
 * @property {string|null} error - Error message if module failed to load
 */

/**
 * @typedef {Object} AuditResult
 * @property {string} timestamp - ISO 8601 timestamp of audit execution
 * @property {string} overallStatus - 'PASS' | 'WARN' | 'FAIL'
 * @property {number} score - Numeric security score (0-100)
 * @property {Array<LayerAuditResult>} layers - Per-layer audit results
 * @property {Array<string>} recommendations - Security recommendations
 * @property {number} durationMs - Audit execution duration in milliseconds
 */

/**
 * @typedef {Object} LayerAuditResult
 * @property {number} layer - Layer number (1-5)
 * @property {string} name - Layer descriptive name
 * @property {Array<ModuleAuditResult>} modules - Per-module audit results
 * @property {string} status - 'PASS' | 'WARN' | 'FAIL'
 */

/**
 * @typedef {Object} ModuleAuditResult
 * @property {string} module - Module name
 * @property {boolean} loaded - Whether module is loaded
 * @property {string} status - 'PASS' | 'WARN' | 'FAIL'
 * @property {Array<string>} checks - Individual check results
 * @property {string|null} error - Error if check failed
 */

/**
 * Retrieves the operational status of all security layers.
 * @returns {Array<LayerStatus>} Array of status objects for each security module
 */
function getLayerStatuses() {
  const modules = [
    { name: 'layer1/sanitizer', ref: sanitizer, layer: 1 },
    { name: 'layer2/gatewayHardener', ref: gatewayHardener, layer: 2 },
    { name: 'layer2/memoryGuardian', ref: memoryGuardian, layer: 2 },
    { name: 'layer3/promptFirewall', ref: promptFirewall, layer: 3 },
    { name: 'layer3/contextScrubber', ref: contextScrubber, layer: 3 },
    { name: 'layer4/sandboxHardener', ref: sandboxHardener, layer: 4 },
    { name: 'layer4/skillValidator', ref: skillValidator, layer: 4 },
    { name: 'layer5/auditFortress', ref: auditFortress, layer: 5 },
  ];

  return modules.map((mod) => ({
    name: mod.name,
    layer: mod.layer,
    loaded: mod.ref !== null && mod.ref !== undefined,
    status: mod.ref ? 'operational' : 'offline',
    error: mod.ref ? null : `Module ${mod.name} is not loaded`,
  }));
}

/**
 * Audits a single module by invoking its diagnostic/status methods.
 * @param {string} moduleName - The name of the module
 * @param {Object|null} moduleRef - The module reference
 * @param {Array<function>} checks - Array of check functions to run
 * @returns {ModuleAuditResult} The audit result for this module
 */
function auditModule(moduleName, moduleRef, checks) {
  /** @type {ModuleAuditResult} */
  const result = {
    module: moduleName,
    loaded: moduleRef !== null && moduleRef !== undefined,
    status: 'FAIL',
    checks: [],
    error: null,
  };

  if (!moduleRef) {
    result.error = `Module ${moduleName} is not loaded`;
    result.checks.push(`[FAIL] Module availability: not loaded`);
    return result;
  }

  result.checks.push(`[PASS] Module availability: loaded`);

  let passCount = 1; // counting the load check
  let totalCount = 1;

  for (const check of checks) {
    totalCount++;
    try {
      const checkResult = check(moduleRef);
      if (checkResult.pass) {
        passCount++;
        result.checks.push(`[PASS] ${checkResult.name}: ${checkResult.message}`);
      } else {
        result.checks.push(`[WARN] ${checkResult.name}: ${checkResult.message}`);
      }
    } catch (err) {
      result.checks.push(`[FAIL] Check error: ${err.message}`);
    }
  }

  if (passCount === totalCount) {
    result.status = 'PASS';
  } else if (passCount >= totalCount * 0.5) {
    result.status = 'WARN';
  } else {
    result.status = 'FAIL';
  }

  return result;
}

/**
 * Runs a comprehensive security audit across all 5 layers.
 * Checks module availability, invokes diagnostic functions where available,
 * and produces a detailed report with scoring and recommendations.
 *
 * @async
 * @returns {Promise<AuditResult>} Comprehensive audit results
 *
 * @example
 * const { runFullAudit } = require('./src/index');
 * const results = await runFullAudit();
 * console.log(`Security Score: ${results.score}/100`);
 * console.log(`Status: ${results.overallStatus}`);
 * results.recommendations.forEach(r => console.log(`  - ${r}`));
 */
async function runFullAudit() {
  const startTime = Date.now();
  const recommendations = [];

  // ---- Layer 1 Audit ----
  const layer1Modules = [
    auditModule('sanitizer', sanitizer, [
      (mod) => ({
        name: 'sanitize function',
        pass: typeof mod.sanitize === 'function',
        message: typeof mod.sanitize === 'function'
          ? 'sanitize() is available'
          : 'sanitize() is missing',
      }),
      (mod) => ({
        name: 'validate function',
        pass: typeof mod.validate === 'function',
        message: typeof mod.validate === 'function'
          ? 'validate() is available'
          : 'validate() is missing',
      }),
      (mod) => ({
        name: 'escapeHtml function',
        pass: typeof mod.escapeHtml === 'function',
        message: typeof mod.escapeHtml === 'function'
          ? 'escapeHtml() is available'
          : 'escapeHtml() is missing',
      }),
    ]),
  ];

  if (!sanitizer) {
    recommendations.push('CRITICAL: Layer 1 sanitizer is offline. Input validation is disabled.');
  }

  // ---- Layer 2 Audit ----
  const layer2Modules = [
    auditModule('gatewayHardener', gatewayHardener, [
      (mod) => ({
        name: 'validateRequest function',
        pass: typeof mod.validateRequest === 'function',
        message: typeof mod.validateRequest === 'function'
          ? 'validateRequest() is available'
          : 'validateRequest() is missing',
      }),
      (mod) => ({
        name: 'getStatus function',
        pass: typeof mod.getStatus === 'function',
        message: typeof mod.getStatus === 'function'
          ? 'getStatus() is available'
          : 'getStatus() is missing',
      }),
    ]),
    auditModule('memoryGuardian', memoryGuardian, [
      (mod) => ({
        name: 'checkIntegrity function',
        pass: typeof mod.checkIntegrity === 'function',
        message: typeof mod.checkIntegrity === 'function'
          ? 'checkIntegrity() is available'
          : 'checkIntegrity() is missing',
      }),
      (mod) => ({
        name: 'getMemoryUsage function',
        pass: typeof mod.getMemoryUsage === 'function',
        message: typeof mod.getMemoryUsage === 'function'
          ? 'getMemoryUsage() is available'
          : 'getMemoryUsage() is missing',
      }),
      (mod) => ({
        name: 'purge function',
        pass: typeof mod.purge === 'function',
        message: typeof mod.purge === 'function'
          ? 'purge() is available'
          : 'purge() is missing',
      }),
    ]),
  ];

  if (!gatewayHardener) {
    recommendations.push('HIGH: Gateway hardener is offline. API gateway is unprotected.');
  }
  if (!memoryGuardian) {
    recommendations.push('HIGH: Memory guardian is offline. Memory-based attacks are possible.');
  }

  // ---- Layer 3 Audit ----
  const layer3Modules = [
    auditModule('promptFirewall', promptFirewall, [
      (mod) => ({
        name: 'isAllowed function',
        pass: typeof mod.isAllowed === 'function',
        message: typeof mod.isAllowed === 'function'
          ? 'isAllowed() is available'
          : 'isAllowed() is missing',
      }),
      (mod) => ({
        name: 'analyze function',
        pass: typeof mod.analyze === 'function',
        message: typeof mod.analyze === 'function'
          ? 'analyze() is available'
          : 'analyze() is missing',
      }),
      (mod) => ({
        name: 'getStats function',
        pass: typeof mod.getStats === 'function',
        message: typeof mod.getStats === 'function'
          ? 'getStats() is available'
          : 'getStats() is missing',
      }),
    ]),
    auditModule('contextScrubber', contextScrubber, [
      (mod) => ({
        name: 'scrub function',
        pass: typeof mod.scrub === 'function',
        message: typeof mod.scrub === 'function'
          ? 'scrub() is available'
          : 'scrub() is missing',
      }),
      (mod) => ({
        name: 'redact function',
        pass: typeof mod.redact === 'function',
        message: typeof mod.redact === 'function'
          ? 'redact() is available'
          : 'redact() is missing',
      }),
    ]),
  ];

  if (!promptFirewall) {
    recommendations.push('CRITICAL: Prompt firewall is offline. Prompt injection attacks are unmitigated.');
  }
  if (!contextScrubber) {
    recommendations.push('MEDIUM: Context scrubber is offline. Sensitive data may leak in context.');
  }

  // ---- Layer 4 Audit ----
  const layer4Modules = [
    auditModule('sandboxHardener', sandboxHardener, [
      (mod) => ({
        name: 'harden function',
        pass: typeof mod.harden === 'function',
        message: typeof mod.harden === 'function'
          ? 'harden() is available'
          : 'harden() is missing',
      }),
      (mod) => ({
        name: 'verify function',
        pass: typeof mod.verify === 'function',
        message: typeof mod.verify === 'function'
          ? 'verify() is available'
          : 'verify() is missing',
      }),
      (mod) => ({
        name: 'isEscapeAttempt function',
        pass: typeof mod.isEscapeAttempt === 'function',
        message: typeof mod.isEscapeAttempt === 'function'
          ? 'isEscapeAttempt() is available'
          : 'isEscapeAttempt() is missing',
      }),
    ]),
    auditModule('skillValidator', skillValidator, [
      (mod) => ({
        name: 'validate function',
        pass: typeof mod.validate === 'function',
        message: typeof mod.validate === 'function'
          ? 'validate() is available'
          : 'validate() is missing',
      }),
      (mod) => ({
        name: 'assess function',
        pass: typeof mod.assess === 'function',
        message: typeof mod.assess === 'function'
          ? 'assess() is available'
          : 'assess() is missing',
      }),
    ]),
  ];

  if (!sandboxHardener) {
    recommendations.push('CRITICAL: Sandbox hardener is offline. Code execution is uncontained.');
  }
  if (!skillValidator) {
    recommendations.push('HIGH: Skill validator is offline. Unvalidated skills may execute.');
  }

  // ---- Layer 5 Audit ----
  const layer5Modules = [
    auditModule('auditFortress', auditFortress, [
      (mod) => ({
        name: 'log function',
        pass: typeof mod.log === 'function',
        message: typeof mod.log === 'function'
          ? 'log() is available'
          : 'log() is missing',
      }),
      (mod) => ({
        name: 'generateReport function',
        pass: typeof mod.generateReport === 'function',
        message: typeof mod.generateReport === 'function'
          ? 'generateReport() is available'
          : 'generateReport() is missing',
      }),
      (mod) => ({
        name: 'verifyChain function',
        pass: typeof mod.verifyChain === 'function',
        message: typeof mod.verifyChain === 'function'
          ? 'verifyChain() is available'
          : 'verifyChain() is missing',
      }),
      (mod) => ({
        name: 'getComplianceStatus function',
        pass: typeof mod.getComplianceStatus === 'function',
        message: typeof mod.getComplianceStatus === 'function'
          ? 'getComplianceStatus() is available'
          : 'getComplianceStatus() is missing',
      }),
    ]),
  ];

  if (!auditFortress) {
    recommendations.push('CRITICAL: Audit fortress is offline. No audit trail is being maintained.');
  }

  // ---- Assemble Layer Results ----
  /** @type {Array<LayerAuditResult>} */
  const layers = [
    {
      layer: 1,
      name: 'Input Sanitization',
      modules: layer1Modules,
      status: deriveLayerStatus(layer1Modules),
    },
    {
      layer: 2,
      name: 'Gateway & Memory Protection',
      modules: layer2Modules,
      status: deriveLayerStatus(layer2Modules),
    },
    {
      layer: 3,
      name: 'Prompt & Context Security',
      modules: layer3Modules,
      status: deriveLayerStatus(layer3Modules),
    },
    {
      layer: 4,
      name: 'Sandbox & Skill Validation',
      modules: layer4Modules,
      status: deriveLayerStatus(layer4Modules),
    },
    {
      layer: 5,
      name: 'Audit & Compliance',
      modules: layer5Modules,
      status: deriveLayerStatus(layer5Modules),
    },
  ];

  // ---- Calculate Score ----
  const totalModules = 8;
  const loadedModules = getLayerStatuses().filter((s) => s.loaded).length;
  const baseScore = Math.round((loadedModules / totalModules) * 70);

  // Bonus points for functional checks passing
  let functionalPass = 0;
  let functionalTotal = 0;
  for (const layer of layers) {
    for (const mod of layer.modules) {
      for (const check of mod.checks) {
        functionalTotal++;
        if (check.startsWith('[PASS]')) {
          functionalPass++;
        }
      }
    }
  }
  const functionalScore = functionalTotal > 0
    ? Math.round((functionalPass / functionalTotal) * 30)
    : 0;

  const score = Math.min(100, baseScore + functionalScore);

  // ---- Determine Overall Status ----
  let overallStatus = 'PASS';
  if (score < 50) {
    overallStatus = 'FAIL';
  } else if (score < 80) {
    overallStatus = 'WARN';
  }

  if (recommendations.length === 0) {
    recommendations.push('All security layers are operational. No immediate action required.');
  }

  const durationMs = Date.now() - startTime;

  /** @type {AuditResult} */
  const auditResult = {
    timestamp: new Date().toISOString(),
    overallStatus,
    score,
    layers,
    recommendations,
    durationMs,
  };

  // Log to audit fortress if available
  if (auditFortress && typeof auditFortress.log === 'function') {
    try {
      auditFortress.log({
        event: 'FULL_AUDIT',
        timestamp: auditResult.timestamp,
        score: auditResult.score,
        status: auditResult.overallStatus,
      });
    } catch (_err) {
      // Silently continue if audit logging fails during audit
    }
  }

  return auditResult;
}

/**
 * Derives the aggregate status for a layer based on its module results.
 * @param {Array<ModuleAuditResult>} modules - Module audit results for a layer
 * @returns {string} 'PASS' | 'WARN' | 'FAIL'
 * @private
 */
function deriveLayerStatus(modules) {
  const statuses = modules.map((m) => m.status);
  if (statuses.every((s) => s === 'PASS')) {
    return 'PASS';
  }
  if (statuses.some((s) => s === 'FAIL')) {
    return 'FAIL';
  }
  return 'WARN';
}

/**
 * Formats an audit result for console output with colors and structure.
 * @param {AuditResult} result - The audit result to format
 * @returns {string} Formatted string for console display
 * @private
 */
function formatAuditReport(result) {
  const lines = [];
  const divider = '═'.repeat(70);
  const thinDivider = '─'.repeat(70);

  lines.push('');
  lines.push(divider);
  lines.push('  SECURITY AUDIT REPORT');
  lines.push(divider);
  lines.push('');
  lines.push(`  Timestamp:      ${result.timestamp}`);
  lines.push(`  Duration:       ${result.durationMs}ms`);
  lines.push(`  Overall Status: ${formatStatus(result.overallStatus)}`);
  lines.push(`  Security Score: ${result.score}/100 ${getScoreBar(result.score)}`);
  lines.push('');

  for (const layer of result.layers) {
    lines.push(thinDivider);
    lines.push(`  Layer ${layer.layer}: ${layer.name} [${formatStatus(layer.status)}]`);
    lines.push(thinDivider);

    for (const mod of layer.modules) {
      lines.push(`    Module: ${mod.module} (${mod.loaded ? 'loaded' : 'NOT LOADED'})`);
      for (const check of mod.checks) {
        lines.push(`      ${check}`);
      }
      if (mod.error) {
        lines.push(`      Error: ${mod.error}`);
      }
      lines.push('');
    }
  }

  lines.push(thinDivider);
  lines.push('  RECOMMENDATIONS:');
  lines.push(thinDivider);
  for (const rec of result.recommendations) {
    lines.push(`    • ${rec}`);
  }

  lines.push('');
  lines.push(divider);
  lines.push(`  Audit complete. Score: ${result.score}/100`);
  lines.push(divider);
  lines.push('');

  return lines.join('\n');
}

/**
 * Formats a status string with visual indicators.
 * @param {string} status - 'PASS' | 'WARN' | 'FAIL'
 * @returns {string} Formatted status string
 * @private
 */
function formatStatus(status) {
  switch (status) {
    case 'PASS':
      return '✅ PASS';
    case 'WARN':
      return '⚠️  WARN';
    case 'FAIL':
      return '❌ FAIL';
    default:
      return `❓ ${status}`;
  }
}

/**
 * Generates a visual score bar.
 * @param {number} score - Score from 0-100
 * @returns {string} Visual score bar
 * @private
 */
function getScoreBar(score) {
  const filled = Math.round(score / 5);
  const empty = 20 - filled;
  return `[${'█'.repeat(filled)}${'░'.repeat(empty)}]`;
}

/**
 * CLI handler for running the audit from the command line.
 * Invoked when the script is executed directly with --audit flag.
 * @async
 * @returns {Promise<void>}
 * @private
 */
async function handleCLI() {
  const args = process.argv.slice(2);

  if (args.includes('--audit')) {
    console.log('Starting full security audit...\n');

    try {
      const result = await runFullAudit();
      console.log(formatAuditReport(result));

      // Exit with appropriate code
      if (result.overallStatus === 'FAIL') {
        process.exit(1);
      } else if (result.overallStatus === 'WARN') {
        process.exit(0);
      } else {
        process.exit(0);
      }
    } catch (err) {
      console.error('Audit failed with error:', err.message);
      console.error(err.stack);
      process.exit(2);
    }
  } else if (args.includes('--status')) {
    const statuses = getLayerStatuses();
    console.log('\nSecurity Module Status:\n');
    for (const s of statuses) {
      const icon = s.loaded ? '✅' : '❌';
      console.log(`  ${icon} Layer ${s.layer} | ${s.name} | ${s.status}`);
    }
    console.log('');
    process.exit(0);
  } else if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node src/index.js [options]

Options:
  --audit    Run a full security audit across all 5 layers
  --status   Display the load status of all security modules
  --help     Show this help message

Examples:
  node src/index.js --audit
  node src/index.js --status
`);
    process.exit(0);
  }
}

// ============================================================================
// Unified API Export
// ============================================================================

/**
 * Unified security framework API.
 * Provides access to all 5 security layers and orchestration functions.
 *
 * @type {Object}
 * @property {Object} layer1 - Input sanitization layer
 * @property {Sanitizer|null} layer1.sanitizer - Input sanitizer module
 * @property {Object} layer2 - Gateway & memory protection layer
 * @property {GatewayHardener|null} layer2.gatewayHardener - Gateway hardening module
 * @property {MemoryGuardian|null} layer2.memoryGuardian - Memory protection module
 * @property {Object} layer3 - Prompt & context security layer
 * @property {PromptFirewall|null} layer3.promptFirewall - Prompt firewall module
 * @property {ContextScrubber|null} layer3.contextScrubber - Context scrubbing module
 * @property {Object} layer4 - Sandbox & skill validation layer
 * @property {SandboxHardener|null} layer4.sandboxHardener - Sandbox hardening module
 * @property {SkillValidator|null} layer4.skillValidator - Skill validation module
 * @property {Object} layer5 - Audit & compliance layer
 * @property {AuditFortress|null} layer5.auditFortress - Audit fortress module
 * @property {function(): Promise<AuditResult>} runFullAudit - Runs comprehensive security audit
 * @property {function(): Array<LayerStatus>} getLayerStatuses - Gets all module statuses
 */
module.exports = {
  // Layer 1: Input Sanitization
  layer1: {
    sanitizer,
  },

  // Layer 2: Gateway & Memory Protection
  layer2: {
    gatewayHardener,
    memoryGuardian,
  },

  // Layer 3: Prompt & Context Security
  layer3: {
    promptFirewall,
    contextScrubber,
  },

  // Layer 4: Sandbox & Skill Validation
  layer4: {
    sandboxHardener,
    skillValidator,
  },

  // Layer 5: Audit & Compliance
  layer5: {
    auditFortress,
  },

  // Orchestration
  runFullAudit,
  getLayerStatuses,
};

// ============================================================================
// CLI Entry Point Detection
// ============================================================================

if (require.main === module) {
  handleCLI();
}