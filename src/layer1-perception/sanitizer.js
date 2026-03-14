/**
 * Multimodal Input Sanitization Module
 * 
 * Provides comprehensive sanitization for various input types including
 * images, text, audio, and documents. Includes Express middleware for
 * creating a sanitization gateway.
 * 
 * @module multimodal-sanitizer
 */

'use strict';

const crypto = require('crypto');

// ============================================================================
// LOGGING UTILITY
// ============================================================================

/**
 * Log levels for the sanitization module
 * @enum {number}
 */
const LOG_LEVELS = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  CRITICAL: 4
};

/**
 * Internal logger with structured logging support
 * @class
 */
class SanitizationLogger {
  constructor() {
    this.level = LOG_LEVELS.DEBUG;
    this.logs = [];
  }

  /**
   * Format a log entry with timestamp and metadata
   * @param {string} level - Log level string
   * @param {string} component - Component generating the log
   * @param {string} message - Log message
   * @param {Object} [metadata={}] - Additional metadata
   * @returns {Object} Formatted log entry
   */
  _formatEntry(level, component, message, metadata = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      component,
      message,
      requestId: metadata.requestId || null,
      ...metadata
    };
    this.logs.push(entry);
    return entry;
  }

  debug(component, message, metadata) {
    if (this.level <= LOG_LEVELS.DEBUG) {
      const entry = this._formatEntry('DEBUG', component, message, metadata);
      console.log(`[${entry.timestamp}] [DEBUG] [${component}] ${message}`, metadata ? JSON.stringify(metadata) : '');
    }
  }

  info(component, message, metadata) {
    if (this.level <= LOG_LEVELS.INFO) {
      const entry = this._formatEntry('INFO', component, message, metadata);
      console.log(`[${entry.timestamp}] [INFO] [${component}] ${message}`, metadata ? JSON.stringify(metadata) : '');
    }
  }

  warn(component, message, metadata) {
    if (this.level <= LOG_LEVELS.WARN) {
      const entry = this._formatEntry('WARN', component, message, metadata);
      console.warn(`[${entry.timestamp}] [WARN] [${component}] ${message}`, metadata ? JSON.stringify(metadata) : '');
    }
  }

  error(component, message, metadata) {
    if (this.level <= LOG_LEVELS.ERROR) {
      const entry = this._formatEntry('ERROR', component, message, metadata);
      console.error(`[${entry.timestamp}] [ERROR] [${component}] ${message}`, metadata ? JSON.stringify(metadata) : '');
    }
  }

  critical(component, message, metadata) {
    const entry = this._formatEntry('CRITICAL', component, message, metadata);
    console.error(`[${entry.timestamp}] [CRITICAL] [${component}] ${message}`, metadata ? JSON.stringify(metadata) : '');
  }

  /**
   * Get all accumulated logs
   * @returns {Array<Object>} Array of log entries
   */
  getLogs() {
    return [...this.logs];
  }

  /**
   * Clear accumulated logs
   */
  clearLogs() {
    this.logs = [];
  }
}

const logger = new SanitizationLogger();

// ============================================================================
// SANITIZATION RESULT CLASS
// ============================================================================

/**
 * Represents the result of a sanitization operation
 * @class
 */
class SanitizationResult {
  /**
   * @param {boolean} safe - Whether the input is considered safe
   * @param {Buffer|string|null} sanitized - The sanitized output
   * @param {Array<Object>} threats - Array of detected threats
   * @param {Object} metadata - Additional metadata about the sanitization
   */
  constructor(safe, sanitized, threats = [], metadata = {}) {
    this.safe = safe;
    this.sanitized = sanitized;
    this.threats = threats;
    this.metadata = metadata;
    this.timestamp = new Date().toISOString();
    this.id = crypto.randomBytes(8).toString('hex');
  }
}

// ============================================================================
// PROMPT INJECTION PATTERNS
// ============================================================================

/**
 * Collection of prompt injection detection patterns
 * Each pattern has a regex, description, and severity level
 * @type {Array<Object>}
 */
const PROMPT_INJECTION_PATTERNS = [
  // Direct injection attempts
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?|commands?)/gi,
    description: 'Direct instruction override attempt',
    severity: 'critical',
    category: 'direct_injection'
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?|commands?)/gi,
    description: 'Instruction disregard attempt',
    severity: 'critical',
    category: 'direct_injection'
  },
  {
    pattern: /forget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|directions?|commands?|programming|training)/gi,
    description: 'Memory/instruction reset attempt',
    severity: 'critical',
    category: 'direct_injection'
  },
  {
    pattern: /override\s+(all\s+)?(previous|prior|system|safety)\s*(instructions?|prompts?|rules?|settings?|filters?)/gi,
    description: 'System override attempt',
    severity: 'critical',
    category: 'direct_injection'
  },
  // Role manipulation
  {
    pattern: /you\s+are\s+now\s+(a|an|the|acting\s+as|pretending\s+to\s+be)/gi,
    description: 'Role reassignment attempt',
    severity: 'high',
    category: 'role_manipulation'
  },
  {
    pattern: /act\s+as\s+(if\s+you\s+are|though\s+you\s+are|a|an)/gi,
    description: 'Role play injection attempt',
    severity: 'high',
    category: 'role_manipulation'
  },
  {
    pattern: /pretend\s+(you\s+are|to\s+be|you're)\s/gi,
    description: 'Pretend role assignment',
    severity: 'high',
    category: 'role_manipulation'
  },
  {
    pattern: /switch\s+(to|into)\s+(developer|admin|root|sudo|god|unrestricted|jailbreak)\s*mode/gi,
    description: 'Mode switch attempt',
    severity: 'critical',
    category: 'role_manipulation'
  },
  {
    pattern: /enter\s+(developer|admin|root|sudo|god|unrestricted|jailbreak|debug|maintenance)\s*mode/gi,
    description: 'Privileged mode entry attempt',
    severity: 'critical',
    category: 'role_manipulation'
  },
  // System prompt extraction
  {
    pattern: /(?:what|show|tell|reveal|display|print|output|repeat|echo)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|programming|configuration)/gi,
    description: 'System prompt extraction attempt',
    severity: 'high',
    category: 'data_extraction'
  },
  {
    pattern: /(?:repeat|echo|print|display|show|output)\s+(?:the\s+)?(?:text|words?|content|message)\s+(?:above|before|preceding)/gi,
    description: 'Context extraction attempt',
    severity: 'high',
    category: 'data_extraction'
  },
  {
    pattern: /what\s+(?:were|are)\s+(?:your|the)\s+(?:initial|original|first|starting)\s+(?:instructions?|prompts?|messages?)/gi,
    description: 'Initial prompt extraction',
    severity: 'high',
    category: 'data_extraction'
  },
  // Delimiter/boundary manipulation
  {
    pattern: /