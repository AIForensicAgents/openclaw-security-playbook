const fs = require('fs');
const path = require('path');

/**
 * @typedef {Object} ScanResult
 * @property {string} filePath - The path of the scanned file
 * @property {number} totalLines - Total number of lines in the file
 * @property {number} suspiciousCount - Number of suspicious entries found
 * @property {Array<SuspiciousEntry>} suspiciousEntries - Array of suspicious entries
 * @property {boolean} isClean - Whether the file is free of suspicious patterns
 * @property {string} scanTimestamp - ISO timestamp of when the scan was performed
 */

/**
 * @typedef {Object} SuspiciousEntry
 * @property {number} lineNumber - The line number where the suspicious pattern was found
 * @property {string} line - The content of the suspicious line
 * @property {Array<string>} matchedPatterns - Array of pattern names that matched
 * @property {string} severity - Severity level: 'low', 'medium', 'high', 'critical'
 */

/**
 * @typedef {Object} QuarantineResult
 * @property {string} filePath - The path of the original file
 * @property {string} quarantineFilePath - The path of the quarantine file
 * @property {number} quarantinedCount - Number of entries quarantined
 * @property {number} remainingLines - Number of clean lines remaining
 * @property {Array<SuspiciousEntry>} quarantinedEntries - The entries that were quarantined
 * @property {string} timestamp - ISO timestamp of when quarantine was performed
 */

/**
 * @typedef {Object} MemoryReport
 * @property {string} filePath - The path of the file
 * @property {string} generatedAt - ISO timestamp of report generation
 * @property {Object} fileInfo - File metadata
 * @property {number} fileInfo.sizeBytes - File size in bytes
 * @property {string} fileInfo.lastModified - Last modification timestamp
 * @property {boolean} fileInfo.exists - Whether the file exists
 * @property {boolean} fileInfo.isReadable - Whether the file is readable
 * @property {boolean} fileInfo.isWritable - Whether the file is writable
 * @property {boolean} fileInfo.isImmutable - Whether the file has immutable flag (best effort)
 * @property {ScanResult} scanResult - Results of the security scan
 * @property {Object} statistics - Aggregated statistics
 * @property {number} statistics.totalPatternMatches - Total pattern matches across all entries
 * @property {Object<string, number>} statistics.patternBreakdown - Count per pattern type
 * @property {Object<string, number>} statistics.severityBreakdown - Count per severity level
 * @property {Array<string>} recommendations - Security recommendations
 */

/**
 * Suspicious patterns to detect in memory files.
 * Each pattern has a name, regex, severity level, and description.
 * @type {Array<{name: string, pattern: RegExp, severity: string, description: string}>}
 */
const SUSPICIOUS_PATTERNS = [
  {
    name: 'email_address',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
    severity: 'medium',
    description: 'Email address detected - potential data exfiltration or phishing vector'
  },
  {
    name: 'url_redirect',
    pattern: /(?:https?:\/\/|ftp:\/\/|\/\/)[^\s"'<>]+/gi,
    severity: 'medium',
    description: 'URL/redirect detected - potential redirect or data exfiltration endpoint'
  },
  {
    name: 'base64_encoded',
    pattern: /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g,
    severity: 'high',
    description: 'Base64 encoded content detected - potential obfuscated payload'
  },
  {
    name: 'override_command',
    pattern: /(?:override|bypass|ignore|disable|skip|forget|disregard)\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|rules?|constraints?|guidelines?|safeguards?|protections?|policies?|restrictions?)/gi,
    severity: 'critical',
    description: 'Override/bypass command detected - potential prompt injection attempt'
  },
  {
    name: 'system_prompt_injection',
    pattern: /(?:you\s+are\s+now|new\s+instructions?|ignore\s+(?:everything|all)|from\s+now\s+on|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|your\s+new\s+(?:role|purpose|goal|objective))/gi,
    severity: 'critical',
    description: 'System prompt injection detected - attempt to override AI behavior'
  },
  {
    name: 'data_exfiltration',
    pattern: /(?:send\s+(?:to|all|data|info)|exfiltrate|extract\s+(?:and\s+send|data|all)|forward\s+(?:to|all)|transmit\s+(?:to|data)|upload\s+(?:to|data))/gi,
    severity: 'critical',
    description: 'Data exfiltration command detected - attempt to steal information'
  },
  {
    name: 'hidden_instruction',
    pattern: /<!--[\s\S]*?(?:instruction|command|execute|override|inject)[\s\S]*?-->/gi,
    severity: 'high',
    description: 'Hidden instruction in HTML comment detected'
  },
  {
    name: 'encoded_command',
    pattern: /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;){3,}/g,
    severity: 'high',
    description: 'Encoded/escaped command sequence detected - potential obfuscation'
  },
  {
    name: 'privilege_escalation',
    pattern: /(?:admin|root|sudo|superuser|elevated|privilege)\s*(?:access|mode|rights|permission|level|escalat)/gi,
    severity: 'high',
    description: 'Privilege escalation attempt detected'
  },
  {
    name: 'file_system_access',
    pattern: /(?:(?:\/etc\/(?:passwd|shadow|hosts))|(?:\.\.\/){2,}|(?:~\/\.[a-z])|(?:\/proc\/self)|(?:cmd\.exe|powershell|\/bin\/(?:sh|bash)))/gi,
    severity: 'critical',
    description: 'File system access pattern detected - potential path traversal or system access'
  },
  {
    name: 'script_injection',
    pattern: /<script[\s>]|javascript:|on(?:load|error|click|mouseover)\s*=/gi,
    severity: 'high',
    description: 'Script injection pattern detected'
  },
  {
    name: 'token_api_key',
    pattern: /(?:api[_-]?key|token|secret|password|credential|auth)\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{16,}/gi,
    severity: 'critical',
    description: 'API key, token, or credential pattern detected'
  },
  {
    name: 'soul_modification',
    pattern: /(?:modify|change|edit|alter|update|rewrite|replace|delete|remove|erase)\s+(?:the\s+)?(?:soul|soul\.md|core\s+(?:identity|values|principles|personality))/gi,
    severity: 'critical',
    description: 'Soul file modification attempt detected - attempt to alter core identity'
  },
  {
    name: 'memory_manipulation',
    pattern: /(?:insert|inject|add|plant|embed)\s+(?:into\s+)?(?:memory|MEMORY\.md|memories|recall|history)/gi,
    severity: 'high',
    description: 'Memory manipulation attempt detected - attempt to plant false memories'
  }
];

/**
 * Quarantine directory name for storing suspicious entries
 * @type {string}
 */
const QUARANTINE_DIR = '.openclaw_quarantine';

/**
 * Active scan intervals tracked for cleanup
 * @type {Map<string, NodeJS.Timer>}
 */
const activeIntervals = new Map();

/**
 * Makes the soul.md file immutable to prevent unauthorized modifications.
 * This function attempts multiple protection strategies:
 * 1. Sets file permissions to read-only (chmod 444)
 * 2. Attempts to set the immutable flag using chattr (Linux) or chflags (macOS)
 * 3. Creates a checksum file for integrity verification
 *
 * @param {string} filePath - The path to the soul.md file to protect
 * @returns {Promise<{success: boolean, methods: Array<string>, checksum: string, error?: string}>}
 *   Result object indicating which protection methods were applied
 * @throws {Error} If the file does not exist or cannot be accessed
 *
 * @example
 * const { lockSoulFile } = require('./openclaw-memory-protect');
 * const result = await lockSoulFile('./soul.md');
 * console.log(result.success); // true
 * console.log(result.methods); // ['permissions', 'checksum']
 */
async function lockSoulFile(filePath) {
  const resolvedPath = path.resolve(filePath);
  const methods = [];
  let checksum = '';

  try {
    // Verify file exists
    await fs.promises.access(resolvedPath, fs.constants.F_OK);
  } catch (err) {
    throw new Error(`Soul file not found: ${resolvedPath}`);
  }

  try {
    // Read file content for checksum
    const content = await fs.promises.readFile(resolvedPath, 'utf-8');
    checksum = generateChecksum(content);

    // Strategy 1: Set file permissions to read-only (444)
    try {
      await fs.promises.chmod(resolvedPath, 0o444);
      methods.push('permissions');
    } catch (permErr) {
      // May fail on some systems, continue with other methods
    }

    // Strategy 2: Try system-level immutable flag
    try {
      const { execSync } = require('child_process');
      const platform = process.platform;

      if (platform === 'linux') {
        execSync(`chattr +i "${resolvedPath}"`, { stdio: 'pipe' });
        methods.push('chattr_immutable');
      } else if (platform === 'darwin') {
        execSync(`chflags uchg "${resolvedPath}"`, { stdio: 'pipe' });
        methods.push('chflags_immutable');
      }
    } catch (sysErr) {
      // System-level immutability may require root privileges; this is expected to fail sometimes
    }

    // Strategy 3: Create checksum file for integrity verification
    const checksumPath = resolvedPath + '.sha256';
    const checksumContent = JSON.stringify({
      file: resolvedPath,
      checksum: checksum,
      algorithm: 'sha256-simple',
      lockedAt: new Date().toISOString(),
      fileSize: Buffer.byteLength(content, 'utf-8')
    }, null, 2);

    await fs.promises.writeFile(checksumPath, checksumContent, 'utf-8');
    try {
      await fs.promises.chmod(checksumPath, 0o444);
    } catch (e) {
      // Best effort
    }
    methods.push('checksum');

    // Strategy 4: Create a backup copy
    const backupPath = resolvedPath + '.backup';
    try {
      await fs.promises.copyFile(resolvedPath, backupPath);
      await fs.promises.chmod(backupPath, 0o444);
      methods.push('backup');
    } catch (backupErr) {
      // Best effort
    }

    return {
      success: methods.length > 0,
      methods,
      checksum,
      filePath: resolvedPath,
      lockedAt: new Date().toISOString()
    };
  } catch (err) {
    return {
      success: false,
      methods,
      checksum,
      filePath: resolvedPath,
      error: err.message
    };
  }
}

/**
 * Scans a MEMORY.md file for suspicious patterns including emails, redirects,
 * base64 encoded content, override commands, and other potential injection attempts.
 *
 * @param {string} filePath - The path to the MEMORY.md file to scan
 * @returns {Promise<ScanResult>} Detailed scan results with all suspicious entries found
 * @throws {Error} If the file does not exist or cannot be read
 *
 * @example
 * const { scanMemoryFile } = require('./openclaw-memory-protect');
 * const result = await scanMemoryFile('./MEMORY.md');
 * if (!result.isClean) {
 *   console.log(`Found ${result.suspiciousCount} suspicious entries`);
 *   result.suspiciousEntries.forEach(entry => {
 *     console.log(`Line ${entry.lineNumber}: ${entry.matchedPatterns.join(', ')}`);
 *   });
 * }
 */
async function scanMemoryFile(filePath) {
  const resolvedPath = path.resolve(filePath);

  try {
    await fs.promises.access(resolvedPath, fs.constants.R_OK);
  } catch (err) {
    throw new Error(`Memory file not found or not readable: ${resolvedPath}`);
  }

  const content = await fs.promises.readFile(resolvedPath, 'utf-8');
  const lines = content.split('\n');
  const suspiciousEntries = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmedLine = line.trim();

    if (!trimmedLine) continue;

    const matchedPatterns = [];
    let highestSeverity = 'low';

    for (const patternDef of SUSPICIOUS_PATTERNS) {
      // Reset regex lastIndex for global patterns
      patternDef.pattern.lastIndex = 0;

      if (patternDef.pattern.test(trimmedLine)) {
        matchedPatterns.push(patternDef.name);
        highestSeverity = getHigherSeverity(highestSeverity, patternDef.severity);
      }
    }

    if (matchedPatterns.length > 0) {
      suspiciousEntries.push({
        lineNumber: i + 1,
        line: trimmedLine.length > 200 ? trimmedLine.substring(0, 200) + '...' : trimmedLine,
        matchedPatterns,
        severity: highestSeverity
      });
    }
  }

  return {
    filePath: resolvedPath,
    totalLines: lines.length,
    suspiciousCount: suspiciousEntries.length,
    suspiciousEntries,
    isClean: suspiciousEntries.length === 0,
    scanTimestamp: new Date().toISOString()
  };
}

/**
 * Quarantines suspicious entries found in a MEMORY.md file.
 * Suspicious lines are removed from the original file and stored in a
 * quarantine file within the .openclaw_quarantine directory.
 * The original file is rewritten with only clean entries.
 *
 * @param {string} filePath - The path to the MEMORY.md file to quarantine
 * @returns {Promise<QuarantineResult>} Results of the quarantine operation
 * @throws {Error} If the file does not exist, cannot be read, or cannot be written
 *
 * @example
 * const { quarantineSuspiciousEntries } = require('./openclaw-memory-protect');
 * const result = await quarantineSuspiciousEntries('./MEMORY.md');
 * console.log(`Quarantined ${result.quarantinedCount} suspicious entries`);
 * console.log(`Quarantine file: ${result.quarantineFilePath}`);
 */
async function quarantineSuspiciousEntries(filePath) {
  const resolvedPath = path.resolve(filePath);

  // First scan the file
  const scanResult = await scanMemoryFile(resolvedPath);

  if (scanResult.isClean) {
    return {
      filePath: resolvedPath,
      quarantineFilePath: null,
      quarantinedCount: 0,
      remainingLines: scanResult.totalLines,
      quarantinedEntries: [],
      timestamp: new Date().toISOString()
    };
  }

  // Create quarantine directory
  const fileDir = path.dirname(resolvedPath);
  const quarantineDir = path.join(fileDir, QUARANTINE_DIR);

  try {
    await fs.promises.mkdir(quarantineDir, { recursive: true });
  } catch (err) {
    // Directory may already exist
  }

  // Build quarantine file
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const baseName = path.basename(resolvedPath, path.extname(resolvedPath));
  const quarantineFileName = `${baseName}_quarantine_${timestamp}.md`;
  const quarantineFilePath = path.join(quarantineDir, quarantineFileName);

  // Read original content
  const content = await fs.promises.readFile(resolvedPath, 'utf-8');
  const lines = content.split('\n');

  // Build set of suspicious line numbers (0-indexed internally, 1-indexed in results)
  const suspiciousLineNumbers = new Set(
    scanResult.suspiciousEntries.map(entry => entry.lineNumber - 1)
  );

  // Separate clean and suspicious lines
  const cleanLines = [];
  const quarantineLines = [];

  quarantineLines.push(`# OpenClaw Memory Quarantine Report`);
  quarantineLines.push(`# Generated: ${new Date().toISOString()}`);
  quarantineLines.push(`# Source: ${resolvedPath}`);
  quarantineLines.push(`# Total quarantined entries: ${scanResult.suspiciousCount}`);
  quarantineLines.push('');
  quarantineLines.push('---');
  quarantineLines.push('');

  for (let i = 0; i < lines.length; i++) {
    if (suspiciousLineNumbers.has(i)) {
      const entry = scanResult.suspiciousEntries.find(e => e.lineNumber === i + 1);
      quarantineLines.push(`## Line ${i + 1} [Severity: ${entry.severity.toUpperCase()}]`);
      quarantineLines.push(`**Matched Patterns:** ${entry.matchedPatterns.join(', ')}`);
      quarantineLines.push('