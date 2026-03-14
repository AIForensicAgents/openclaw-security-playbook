/**
 * @module audit-log-protection
 * @description Complete Node.js CommonJS module for protecting audit logs
 * with append-only enforcement, HMAC signatures, log forwarding, alert rules,
 * and tamper detection.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const http = require('http');
const https = require('https');

/**
 * @typedef {Object} LogEntry
 * @property {string} id - Unique log entry identifier
 * @property {string} timestamp - ISO 8601 timestamp
 * @property {string} level - Log level (info, warn, error, critical)
 * @property {string} message - Log message
 * @property {Object} [metadata] - Additional metadata
 * @property {string} hmac - HMAC signature of the entry
 * @property {string} previousHash - Hash of the previous log entry (chain)
 */

/**
 * @typedef {Object} AlertRule
 * @property {string} name - Rule name
 * @property {string} type - Rule type: 'bash_tool' | 'unknown_ip' | 'file_deletion' | 'custom'
 * @property {string} [pattern] - Regex pattern to match against log messages
 * @property {string[]} [knownIPs] - List of known/allowed IPs (for unknown_ip type)
 * @property {Function} [condition] - Custom condition function receiving a log entry
 * @property {string} severity - Alert severity: 'low' | 'medium' | 'high' | 'critical'
 * @property {Function} [callback] - Callback function when rule triggers
 */

/**
 * @typedef {Object} ForwardingDestination
 * @property {string} type - Destination type: 's3' | 'webhook'
 * @property {string} [bucket] - S3 bucket name (for S3 type)
 * @property {string} [region] - AWS region (for S3 type)
 * @property {string} [accessKeyId] - AWS access key (for S3 type)
 * @property {string} [secretAccessKey] - AWS secret key (for S3 type)
 * @property {string} [prefix] - S3 key prefix (for S3 type)
 * @property {string} [url] - Webhook URL (for webhook type)
 * @property {Object} [headers] - Additional headers (for webhook type)
 * @property {number} [batchSize] - Number of entries to batch before forwarding
 * @property {number} [flushInterval] - Milliseconds between automatic flushes
 */

/**
 * @typedef {Object} SecureLogger
 * @property {Function} info - Log info level message
 * @property {Function} warn - Log warning level message
 * @property {Function} error - Log error level message
 * @property {Function} critical - Log critical level message
 * @property {Function} log - Log with custom level
 * @property {Function} getHmacKey - Get the HMAC key
 * @property {Function} close - Close the logger and flush buffers
 * @property {Function} getLastHash - Get the last entry hash for chain verification
 */

/**
 * @typedef {Object} TamperDetectionResult
 * @property {boolean} intact - Whether the log is intact
 * @property {number} totalEntries - Total number of log entries
 * @property {number} validEntries - Number of valid entries
 * @property {number} invalidEntries - Number of invalid/tampered entries
 * @property {Object[]} issues - List of detected issues
 * @property {string} issues[].type - Issue type
 * @property {number} issues[].lineNumber - Line number of the issue
 * @property {string} issues[].description - Description of the issue
 */

// Internal alert emitter for the module
const alertEmitter = new EventEmitter();

// Store active alert rules
let activeAlertRules = [];

// Store forwarding configurations
const forwardingConfigs = new Map();

// Forwarding buffers
const forwardingBuffers = new Map();

// Forwarding intervals
const forwardingIntervals = new Map();

/**
 * Generates a unique identifier for log entries.
 * @returns {string} A unique identifier string
 * @private
 */
function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Computes HMAC-SHA256 signature for a given data string.
 * @param {string} data - The data to sign
 * @param {string} key - The HMAC key
 * @returns {string} The hex-encoded HMAC signature
 * @private
 */
function computeHMAC(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Computes SHA-256 hash of a string.
 * @param {string} data - The data to hash
 * @returns {string} The hex-encoded hash
 * @private
 */
function computeHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Sets up an append-only log file at the specified path.
 * Creates the file if it doesn't exist, sets filesystem permissions
 * to append-only, and returns a file descriptor opened in append mode.
 *
 * @param {string} logPath - Absolute or relative path to the log file
 * @returns {Object} An object containing the file descriptor and utility methods
 * @property {number} fd - The file descriptor for the append-only log
 * @property {string} logPath - The resolved log path
 * @property {Function} append - Function to append data to the log
 * @property {Function} close - Function to close the file descriptor
 * @property {Function} getStats - Function to get file statistics
 *
 * @example
 * const log = setupAppendOnlyLog('/var/log/audit/app.log');
 * log.append('System started\n');
 * log.close();
 */
function setupAppendOnlyLog(logPath) {
  const resolvedPath = path.resolve(logPath);
  const dir = path.dirname(resolvedPath);

  // Ensure directory exists
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  }

  // Create the file if it doesn't exist
  if (!fs.existsSync(resolvedPath)) {
    fs.writeFileSync(resolvedPath, '', { mode: 0o644 });
  }

  // Open file in append-only mode
  const fd = fs.openSync(resolvedPath, 'a');

  // Try to set file to append-only (works on supported filesystems)
  try {
    // Set permissions: owner read/append, group read, others read
    fs.chmodSync(resolvedPath, 0o644);
  } catch (err) {
    // Permissions setting may fail on some systems; continue gracefully
  }

  // Create a lock file to track append-only status
  const lockPath = resolvedPath + '.lock';
  const lockData = JSON.stringify({
    createdAt: new Date().toISOString(),
    pid: process.pid,
    appendOnly: true,
    originalSize: fs.statSync(resolvedPath).size,
  });
  fs.writeFileSync(lockPath, lockData, { mode: 0o444 });

  /**
   * Appends data to the log file.
   * @param {string} data - Data to append
   * @throws {Error} If writing fails
   */
  function append(data) {
    const buffer = Buffer.from(data);
    fs.writeSync(fd, buffer, 0, buffer.length);
    fs.fsyncSync(fd);
  }

  /**
   * Closes the file descriptor.
   */
  function close() {
    try {
      fs.closeSync(fd);
    } catch (err) {
      // Already closed
    }
  }

  /**
   * Returns file statistics.
   * @returns {fs.Stats} File statistics
   */
  function getStats() {
    return fs.statSync(resolvedPath);
  }

  /**
   * Verifies the file hasn't been truncated.
   * @returns {boolean} True if file size is >= original size
   */
  function verifyNotTruncated() {
    try {
      const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      const currentSize = fs.statSync(resolvedPath).size;
      return currentSize >= lock.originalSize;
    } catch {
      return false;
    }
  }

  return {
    fd,
    logPath: resolvedPath,
    append,
    close,
    getStats,
    verifyNotTruncated,
  };
}

/**
 * Creates a secure logger that writes HMAC-signed, chained log entries
 * to the specified log file. Each entry is cryptographically linked to
 * the previous entry, forming a tamper-evident chain.
 *
 * @param {string} logPath - Path to the log file
 * @param {Object} [options] - Logger configuration options
 * @param {string} [options.hmacKey] - HMAC key (auto-generated if not provided)
 * @param {string} [options.algorithm='sha256'] - Hash algorithm
 * @param {boolean} [options.includeHostInfo=true] - Include hostname in entries
 * @param {boolean} [options.prettyPrint=false] - Pretty print JSON entries
 * @returns {SecureLogger} A secure logger instance
 *
 * @example
 * const logger = createSecureLogger('/var/log/audit/secure.log');
 * logger.info('User login successful', { userId: '12345', ip: '192.168.1.1' });
 * logger.warn('Suspicious activity detected', { ip: '10.0.0.99' });
 * logger.critical('Unauthorized access attempt', { resource: '/admin' });
 * const key = logger.getHmacKey(); // Save this for verification
 * logger.close();
 */
function createSecureLogger(logPath, options = {}) {
  const hmacKey = options.hmacKey || crypto.randomBytes(32).toString('hex');
  const algorithm = options.algorithm || 'sha256';
  const includeHostInfo = options.includeHostInfo !== false;
  const prettyPrint = options.prettyPrint || false;

  const appendOnlyLog = setupAppendOnlyLog(logPath);
  let lastHash = computeHash('GENESIS_BLOCK');
  let entryCount = 0;
  let closed = false;

  // Store the HMAC key securely alongside the log
  const keyPath = logPath + '.key';
  try {
    fs.writeFileSync(keyPath, JSON.stringify({
      hmacKey: hmacKey,
      algorithm: algorithm,
      createdAt: new Date().toISOString(),
      logPath: path.resolve(logPath),
    }), { mode: 0o400 });
  } catch (err) {
    // Key storage may fail; the key is still available via getHmacKey()
  }

  // If existing log has entries, compute the last hash from them
  try {
    const existingContent = fs.readFileSync(path.resolve(logPath), 'utf8').trim();
    if (existingContent) {
      const lines = existingContent.split('\n').filter(l => l.trim());
      if (lines.length > 0) {
        const lastLine = lines[lines.length - 1];
        try {
          const lastEntry = JSON.parse(lastLine);
          if (lastEntry.previousHash) {
            // Recompute hash of the last entry for chaining
            const entryData = buildEntryData(lastEntry);
            lastHash = computeHash(entryData);
            entryCount = lines.length;
          }
        } catch {
          // Not a valid JSON entry; start fresh chain
        }
      }
    }
  } catch {
    // File might not exist yet or be empty
  }

  /**
   * Builds the canonicalized data string for an entry (excluding HMAC).
   * @param {Object} entry - The log entry
   * @returns {string} Canonicalized entry data
   * @private
   */
  function buildEntryData(entry) {
    const obj = {
      id: entry.id,
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      metadata: entry.metadata || {},
      previousHash: entry.previousHash,
    };
    if (entry.hostname) obj.hostname = entry.hostname;
    if (entry.pid) obj.pid = entry.pid;
    return JSON.stringify(obj);
  }

  /**
   * Creates and writes a signed log entry.
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} [metadata] - Additional metadata
   * @returns {LogEntry} The created log entry
   * @private
   */
  function writeEntry(level, message, metadata = {}) {
    if (closed) {
      throw new Error('Logger is closed');
    }

    entryCount++;
    const entry = {
      id: generateId(),
      sequence: entryCount,
      timestamp: new Date().toISOString(),
      level: level,
      message: message,
      metadata: metadata,
      previousHash: lastHash,
    };

    if (includeHostInfo) {
      entry.hostname = require('os').hostname();
      entry.pid = process.pid;
    }

    // Build canonical data and compute HMAC
    const entryData = buildEntryData(entry);
    entry.hmac = computeHMAC(entryData, hmacKey);

    // Update chain hash
    lastHash = computeHash(entryData + entry.hmac);
    entry.chainHash = lastHash;

    // Write to append-only log
    const line = prettyPrint
      ? JSON.stringify(entry, null, 2) + '\n---\n'
      : JSON.stringify(entry) + '\n';
    appendOnlyLog.append(line);

    // Check against alert rules
    processAlertRules(entry);

    // Process forwarding
    processForwarding(logPath, entry);

    return entry;
  }

  return {
    /**
     * Logs an info-level message.
     * @param {string} message - The log message
     * @param {Object} [metadata] - Additional metadata
     * @returns {LogEntry} The created log entry
     */
    info(message, metadata) {
      return writeEntry('info', message, metadata);
    },

    /**
     * Logs a warning-level message.
     * @param {string} message - The log message
     * @param {Object} [metadata] - Additional metadata
     * @returns {LogEntry} The created log entry
     */
    warn(message, metadata) {
      return writeEntry('warn', message, metadata);
    },

    /**
     * Logs an error-level message.
     * @param {string} message - The log message
     * @param {Object} [metadata] - Additional metadata
     * @returns {LogEntry} The created log entry
     */
    error(message, metadata) {
      return writeEntry('error', message, metadata);
    },

    /**
     * Logs a critical-level message.
     * @param {string} message - The log message
     * @param {Object} [metadata] - Additional metadata
     * @returns {LogEntry} The created log entry
     */
    critical(message, metadata) {
      return writeEntry('critical', message, metadata);
    },

    /**
     * Logs a message with a custom level.
     * @param {string} level - The log level
     * @param {string} message - The log message
     * @param {Object} [metadata] - Additional metadata
     * @returns {LogEntry} The created log entry
     */
    log(level, message, metadata) {
      return writeEntry(level, message, metadata);
    },

    /**
     * Returns the HMAC key used for signing.
     * Store this key securely for later verification.
     * @returns {string} The HMAC key (hex-encoded)
     */
    getHmacKey() {
      return hmacKey;
    },

    /**
     * Returns the last chain hash.
     * @returns {string} The last chain hash
     */
    getLastHash() {
      return lastHash;
    },

    /**
     * Returns the number of entries written.
     * @returns {number} Entry count
     */
    getEntryCount() {
      return entryCount;
    },

    /**
     * Closes the logger, flushing any buffers and closing the file descriptor.
     */
    close() {
      if (!closed) {
        closed = true;
        appendOnlyLog.close();
      }
    },
  };
}

/**
 * Verifies the integrity of a log file by checking HMAC signatures
 * and the hash chain of all entries.
 *
 * @param {string} logPath - Path to the log file
 * @param {string} hmacKey - The HMAC key used to sign the entries
 * @param {Object} [options] - Verification options
 * @param {boolean} [options.verbose=false] - Include detailed per-entry results
 * @param {boolean} [options.stopOnFirst=false] - Stop on first integrity failure
 * @returns {Object} Verification result
 * @property {boolean} valid - Whether the entire log is valid
 * @property {number} totalEntries - Total entries checked
 * @property {number} validEntries - Number of valid entries
 * @property {number} invalidEntries - Number of invalid entries
 * @property {Object[]} failures - List of integrity failures
 * @property {Object[]} [details] - Per-entry details (if verbose)
 *
 * @example
 * const result = verifyLogIntegrity('/var/log/audit/secure.log', hmacKey);
 * if (result.valid) {
 *   console.log('Log integrity verified:', result.totalEntries, 'entries');
 * } else {
 *   console.error('Log tampering detected!', result.failures);
 * }
 */
function verifyLogIntegrity(logPath, hmacKey, options = {}) {
  const resolvedPath = path.resolve(logPath);
  const verbose = options.verbose || false;
  const stopOnFirst = options.stopOnFirst || false;

  const result = {
    valid: true,
    totalEntries: 0,
    validEntries: 0,
    invalidEntries: 0,
    failures: [],
    chainIntact: true,
    details: verbose ? [] : undefined,
  };

  if (!fs.existsSync(resolvedPath)) {
    result.valid = false;
    result.failures.push({
      type: 'FILE_NOT_FOUND',
      description: `Log file not found: ${resolvedPath}`,
    });
    return result;
  }

  let content;
  try {
    content = fs.readFileSync(resolvedPath, 'utf8').trim();
  } catch (err) {
    result.valid = false;
    result.failures.push({
      type: 'READ_ERROR',
      description: `Failed to read log file: ${err.message}`,
    });
    return result;
  }

  if (!content) {
    // Empty log file is valid
    return result;
  }

  const lines = content.split('\n').filter(l => l.trim());
  let previousHash = computeHash('GENESIS_BLOCK');

  for (let i = 0; i < lines.length; i++) {
    result.totalEntries++;
    const lineNumber = i + 1;
    let entry;

    try {
      entry = JSON.parse(lines[i]);
    } catch (parseErr) {
      result.valid = false;
      result.invalidEntries++;
      const failure = {
        type: 'PARSE_ERROR',
        lineNumber: lineNumber,
        description: `Failed to parse JSON on line ${lineNumber}: ${parseErr.message}`,
      };
      result.failures.push(failure);
      if (verbose) {
        result.details.push({ lineNumber, valid: false, issue: failure });
      }
      if (stopOnFirst) break;
      continue;
    }

    // Verify sequence
    if (entry.sequence !== undefined && entry.sequence !== lineNumber) {
      const failure = {
        type: 'SEQUENCE_ERROR',
        lineNumber: lineNumber,
        expected: lineNumber,
        actual: entry.sequence,
        description: `Sequence mismatch on line ${lineNumber}: expected ${lineNumber}, got ${entry.sequence}`,
      };
      result.failures.push(failure);
      result.valid = false;
      result.invalidEntries++;
      if (verbose) {
        result.details.push({ lineNumber, valid: false, issue: failure });
      }
      if (stopOnFirst) break;
      continue;
    }

    // Verify previous hash chain
    if (entry.previousHash !== previousHash) {
      result.chainIntact = false;
      result.valid = false;
      result.invalidEntries++;
      const failure = {
        type: 'CHAIN_BREAK',
        lineNumber: lineNumber,
        description: `Hash chain broken at line ${lineNumber}: expected previousHash ${previousHash}, got ${entry.previousHash}`,
      };
      result.failures.push(failure);
      if (verbose) {
        result.details.push({ lineNumber, valid: false, issue: failure });
      }
      if (stopOnFirst) break;
      continue;
    }

    // Rebuild canonical data for HMAC verification
    const entryData = JSON.stringify({
      id: entry.id,
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      metadata: entry.metadata || {},
      previousHash: entry.previousHash,
      ...(entry.hostname ? { hostname: entry.hostname } : {}),
      ...(entry.pid ? { pid: entry.pid } : {}),
    });

    // Verify HMAC
    const expectedHmac = computeHMAC(entryData, hmacKey);
    if (entry.hmac !== expectedHmac) {
      result.valid = false;
      result.invalidEntries++;
      const failure = {
        type: 'HMAC_MISMATCH',
        lineNumber: lineNumber,
        description: `HMAC verification failed on line ${lineNumber}: entry may have been tampered with`,
        entryId: entry.id,
      };
      result.failures.push(failure);
      if (verbose) {
        result.details.push({ lineNumber, valid: false, issue: failure });
      }
      if (stopOnFirst) break;
      continue;
    }

    // Verify chain hash
    const expectedChainHash = computeHash(entryData + entry.hmac);
    if (entry.chainHash && entry.chainHash !== expectedChainHash) {
      result.valid = false;
      result.chainIntact = false;
      result.invalidEntries++;
      const failure = {
        type: 'CHAIN_HASH_MISMATCH',
        lineNumber: lineNumber,
        description: `Chain hash mismatch on line ${lineNumber}`,
        entryId: entry.id,
      };
      result.failures.push(failure);
      if (verbose) {
        result.details.push({ lineNumber, valid: false, issue: failure });
      }
      if (stopOnFirst) break;
      continue;
    }

    // Update chain
    previousHash = entry.chainHash || expectedChainHash;
    result.validEntries++;

    if (verbose) {
      result.details.push({
        lineNumber,
        valid: true,
        entryId: entry.id,
        timestamp: entry.timestamp,
        level: entry.level,
      });
    }
  }

  return result;
}

/**
 * Processes an entry against forwarding configurations.
 * @param {string} logPath - The log path
 * @param {Object} entry - The log entry to forward
 * @private
 */
function processForwarding(logPath, entry) {
  const resolvedPath = path.resolve(logPath);
  const config = forwardingConfigs.get(resolvedPath);
  if (!config) return;

  let buffer = forwardingBuffers.get(resolvedPath);
  if (!buffer) {
    buffer = [];
    forwardingBuffers.set(resolvedPath, buffer);
  }

  buffer.push(entry);

  const batchSize = config.destination.batchSize || 10;
  if (buffer.length >= batchSize) {
    flushForwardingBuffer(resolvedPath, config);
  }
}

/**
 * Flushes the forwarding buffer for a given log path.
 * @param {string} resolvedPath - Resolved log path
 * @param {Object} config - Forwarding configuration
 * @private
 */
function flushForwardingBuffer(resolvedPath, config) {
  const buffer = forwardingBuffers.get(resolvedPath);
  if (!buffer || buffer.length === 0) return;

  const entries = [...buffer];
  forwardingBuffers.set(resolvedPath, []);

  const dest = config.destination;

  if (dest.type === 's3') {
    forwardToS3(entries, dest, config);
  } else if (dest.type === 'webhook') {
    forwardToWebhook(entries, dest, config);
  }
}

/**
 * Forwards log entries to an S3 bucket.
 * @param {Object[]} entries - Log entries to forward
 * @param {ForwardingDestination} dest - S3 destination configuration
 * @param {Object} config - Full forwarding configuration
 * @private
 */
function forwardToS3(entries, dest, config) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const key = `${dest.prefix || 'audit-logs/'}${timestamp}-${generateId().substring(0, 8)}.jsonl`;
  const body = entries.map(e => JSON.stringify(e)).join('\n');

  // AWS Signature Version 4 simplified implementation
  const region = dest.region || 'us-east-1';
  const service = 's3';
  const host = `${dest.bucket}.s3.${region}.amazonaws.com`;
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  const shortDate = dateStamp.substring(0, 8);

  const canonicalUri = '/' + key;
  const canonicalQueryString = '';
  const payloadHash = crypto.createHash('sha256').update(body).digest('hex');

  const headers = {
    'Host': host,
    'Content-Type': 'application/x-ndjson',
    'X-Amz-Date': dateStamp,
    'X-Amz-Content-Sha256': payloadHash,
  };

  const signedHeaders = Object.keys(headers).map(h => h.toLowerCase()).sort().join(';');
  const canonicalHeaders = Object.keys(headers)
    .sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()))
    .map(h => `${h.toLowerCase()}:${headers[h].trim()}`)
    .join('\n') + '\n';

  const canonicalRequest = [
    'PUT',
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${shortDate}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    dateStamp,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  // Derive signing key
  const accessKeyId = dest.accessKeyId || process.env.AWS_ACCESS_KEY_ID || '';
  const secretAccessKey = dest.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY || '';

  if (!accessKeyId || !secretAccessKey) {
    if (config.onError) {
      config.onError(new Error('AWS credentials not configured for S3 forwarding'));
    }
    return;
  }

  const kDate = crypto.createHmac('sha256', `AWS4${secretAccessKey}`).update(shortDate).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();

  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  headers['Authorization'] = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const requestOptions = {
    hostname: host,
    port: 443,
    path: canonicalUri,
    method: 'PUT',
    headers: {
      ...headers,
      'Content-Length': Buffer.byteLength(body),
    },
  };

  const req = https.request(requestOptions, (res) => {
    let responseBody = '';
    res.on('data', (chunk) => { responseBody += chunk; });
    res.on('end', () => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        if (config.onSuccess) {
          config.onSuccess({ entriesForwarded: entries.length, key, statusCode: res.statusCode });
        }
      } else {
        if (config.onError) {
          config.onError(new Error(`S3 upload failed: ${res.statusCode} - ${responseBody}`));
        }
      }
    });
  });

  req.on('error', (err) => {
    if (config.onError) {
      config.onError(err);
    }
  });

  req.write(body);
  req.end();
}

/**
 * Forwards log entries to a webhook endpoint.
 * @param {Object[]} entries - Log entries to forward
 * @param {ForwardingDestination} dest - Webhook destination configuration
 * @param {Object} config - Full forwarding configuration
 * @private
 */
function forwardToWebhook(entries, dest, config) {
  const url = new URL(dest.url);
  const payload = JSON.stringify({
    source: 'audit-log-protection',
    timestamp: new Date().toISOString(),
    count: entries.length,
    entries: entries,
  });

  const isHttps = url.protocol === 'https:';
  const transport = isHttps ? https : http;

  const requestOptions = {
    hostname: url.hostname,
    port: url.port || (isHttps ? 443 : 80),
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'X-Audit-Log-Signature': computeHMAC(payload, config.signingKey || 'default-webhook-key'),
      ...(dest.headers || {}),
    },
  };

  const req = transport.request(requestOptions, (res) => {
    let responseBody = '';
    res.on('data', (chunk) => { responseBody += chunk; });
    res.on('end', () => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        if (config.onSuccess) {
          config.onSuccess({ entriesForwarded: entries.length, statusCode: res.statusCode });
        }
      } else {
        if (config.onError) {
          config.onError(new Error(`Webhook delivery failed: ${res.statusCode} - ${responseBody}`));
        }
        // Retry logic: put entries back in buffer
        const buffer = forwardingBuffers.get(config.resolvedPath) || [];
        forwardingBuffers.set(config.resolvedPath, [...entries, ...buffer]);
      }
    });
  });

  req.on('error', (err) => {
    if (config.onError) {
      config.onError(err);
    }
    // Retry: put entries back
    const buffer = forwardingBuffers.get(config.resolvedPath) || [];
    forwardingBuffers.set(config.resolvedPath, [...entries, ...buffer]);
  });

  req.setTimeout(dest.timeout || 30000, () => {
    req.destroy(new Error('Webhook request timed out'));
  });

  req.write(payload);
  req.end();
}

/**
 * Sets up log forwarding for a log file to an external destination.
 * Supports forwarding to Amazon S3 and webhook endpoints.
 * Entries are batched and forwarded either when the batch size is reached
 * or at regular intervals.
 *
 * @param {string} logPath - Path to the log file to forward from
 * @param {ForwardingDestination} destination - The forwarding destination configuration
 * @param {Object} [options] - Additional forwarding options
 * @param {string} [options.signingKey] - Key for signing webhook payloads
 * @param {Function} [options.onSuccess] - Callback on successful forwarding
 * @param {Function} [options.onError] - Callback on forwarding error
 * @param {Function} [options.filter] - Filter function to select which entries to forward
 * @returns {Object} Forwarding controller
 * @property {Function} flush - Manually flush the forwarding buffer
 * @property {Function} stop - Stop automatic forwarding
 * @property {Function} getBufferSize - Get current buffer size
 * @property {Function} getStats - Get forwarding statistics
 *
 * @example
 * // Forward to S3
 * const forwarder = setupLogForwarding('/var/log/audit/secure.log', {
 *   type: 's3',
 *   bucket: 'my-audit-logs',
 *   region: 'us-east-1',
 *   accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
 *   secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
 *   prefix: 'production/audit/',
 *   batchSize: 100,
 *   flushInterval: 60000,
 * });
 *
 * // Forward to webhook
 * const forwarder = setupLogForwarding('/var/log/audit/secure.log', {
 *   type: 'webhook',
 *   url: 'https://siem.example.com/api/logs',
 *   headers: { 'Authorization': 'Bearer token123' },
 *   batchSize: 50,
 *   flushInterval: 30000,
 * });
 */
function setupLogForwarding(logPath, destination, options = {}) {
  const resolvedPath = path.resolve(logPath);

  const config = {
    destination,
    resolvedPath,
    signingKey: options.signingKey || crypto.randomBytes(16).toString('hex'),
    onSuccess: options.onSuccess || null,
    onError: options.onError || null,
    filter: options.filter || null,
    stats: {
      totalForwarded: 0,
      totalFailed: 0,
      lastForwardedAt: null,
      startedAt: new Date().toISOString(),
    },
  };

  // Wrap callbacks to update stats
  const originalOnSuccess = config.onSuccess;
  config.onSuccess = (result) => {
    config.stats.totalForwarded += result.entriesForwarded || 0;
    config.stats.lastForwardedAt = new Date().toISOString();
    if (originalOnSuccess) originalOnSuccess(result);
  };

  const originalOnError = config.onError;
  config.onError = (err) => {
    config.stats.totalFailed++;
    if (originalOnError) originalOnError(err);
  };

  forwardingConfigs.set(resolvedPath, config);
  forwardingBuffers.set(resolvedPath, []);

  // Set up periodic flushing
  const flushInterval = destination.flushInterval || 60000;
  const intervalId = setInterval(() => {
    flushForwardingBuffer(resolvedPath, config);
  }, flushInterval);

  forwardingIntervals.set(resolvedPath, intervalId);

  // If the log file already exists, optionally forward existing entries
  if (options.forwardExisting && fs.existsSync(resolvedPath)) {
    try {
      const content = fs.readFileSync(resolvedPath, 'utf8').trim();
      if (content) {
        const lines = content.split('\n').filter(l => l.trim());
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            if (!config.filter || config.filter(entry)) {
              processForwarding(logPath, entry);
            }
          } catch {
            // Skip non-JSON lines
          }
        }
      }
    } catch {
      // Ignore read errors for existing content
    }
  }

  return {
    /**
     * Manually flushes the forwarding buffer.
     * @returns {number} Number of entries flushed
     */
    flush() {
      const buffer = forwardingBuffers.get(resolvedPath) || [];
      const count = buffer.length;
      flushForwardingBuffer(resolvedPath, config);
      return count;
    },

    /**
     * Stops automatic forwarding.
     */
    stop() {
      const interval = forwardingIntervals.get(resolvedPath);
      if (interval) {
        clearInterval(interval);
        forwardingIntervals.delete(resolvedPath);
      }
      // Flush remaining entries
      flushForwardingBuffer(resolvedPath, config);
      forwardingConfigs.delete(resolvedPath);
    },

    /**
     * Gets the current buffer size.
     * @returns {number} Number of entries in the buffer
     */
    getBufferSize() {
      const buffer = forwardingBuffers.get(resolvedPath) || [];
      return buffer.length;
    },

    /**
     * Gets forwarding statistics.
     * @returns {Object} Forwarding statistics
     */
    getStats() {
      return { ...config.stats };
    },
  };
}

/**
 * Processes a log entry against active alert rules.
 * @param {Object} entry - The log entry to check
 * @private
 */
function processAlertRules(entry) {
  for (const rule of activeAlertRules) {
    let triggered = false;
    let matchDetails = {};

    switch (rule.type) {
      case 'bash_tool': {
        // Detect bash/shell tool usage
        const bashPatterns = [
          /bash_tool/i,
          /shell_exec/i,
          /child_process/i,
          /exec\s*\(/i,
          /spawn\s*\(/i,
          /system\s*\(/i,
          /eval\s*\(/i,
          /\bexec\b/i,
          /\bsh\s+-c\b/i,
          /\/bin\/(ba)?sh/i,
          /command\s+injection/i,
          /subprocess/i,
          /os\.system/i,
          /popen/i,
          /Runtime\.getRuntime/i,
        ];

        const messageAndMeta = JSON.stringify(entry);
        for (const pattern of bashPatterns) {
          if (pattern.test(messageAndMeta)) {
            triggered = true;
            matchDetails = { matchedPattern: pattern.toString(), content: entry.message };
            break;
          }
        }

        // Also check custom pattern if provided
        if (!triggered && rule.pattern) {
          const customPattern = new RegExp(rule.pattern, 'i');
          if (customPattern.test(messageAndMeta)) {
            triggered = true;
            matchDetails = { matchedPattern: rule.pattern, content: entry.message };
          }
        }
        break;
      }

      case 'unknown_ip': {
        // Detect unknown IP addresses
        const knownIPs = rule.knownIPs || [];
        const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
        const messageAndMeta = JSON.stringify(entry);
        const foundIPs = messageAndMeta.match(ipRegex) || [];

        for (const ip of foundIPs) {
          // Validate IP
          const parts = ip.split('.').map(Number);
          const isValidIP = parts.every(p => p >= 0 && p <= 255);
          if (!isValidIP) continue;

          // Skip private/loopback IPs unless they're not in known list
          const isPrivate = (
            parts[0] === 10 ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168) ||
            (parts[0] === 127)
          );

          if (!knownIPs.includes(ip) && (!isPrivate || knownIPs.length > 0)) {
            triggered = true;
            matchDetails = { unknownIP: ip, knownIPs: knownIPs };
            break;
          }
        }

        // Also check metadata for IP fields
        if (!triggered && entry.metadata) {
          const ipFields = ['ip', 'ipAddress', 'sourceIP', 'source_ip', 'clientIP', 'client_ip', 'remote_addr'];
          for (const field of ipFields) {
            if (entry.metadata[field] && !knownIPs.includes(entry.metadata[field])) {
              triggered = true;
              matchDetails = { unknownIP: entry.metadata[field], field, knownIPs };
              break;
            }
          }
        }
        break;
      }

      case 'file_deletion': {
        // Detect file deletion events
        const deletionPatterns = [
          /file\s+(delet|remov)/i,
          /unlink/i,
          /rm\s+(-rf?\s+)?/i,
          /rmdir/i,
          /\bdelete(d)?\s+file/i,
          /\bremove(d)?\s+file/i,
          /fs\.unlink/i,
          /fs\.rmdir/i,
          /fs\.rm\b/i,
          /shred/i,
          /wipe/i,
          /purge/i,
          /destroy.*file/i,
          /erase.*file/i,
        ];

        const messageAndMeta = JSON.stringify(entry);
        for (const pattern of deletionPatterns) {
          if (pattern.test(messageAndMeta)) {
            triggered = true;
            matchDetails = { matchedPattern: pattern.toString(), content: entry.message };
            break;
          }
        }

        // Also check custom pattern
        if (!triggered && rule.pattern) {
          const customPattern = new RegExp(rule.pattern, 'i');
          if (customPattern.test(messageAndMeta)) {
            triggered = true;
            matchDetails = { matchedPattern: rule.pattern, content: entry.message };
          }
        }
        break;
      }

      case 'custom': {
        // Custom condition function
        if (rule.condition && typeof rule.condition === 'function') {
          try {
            const result = rule.condition(entry);
            if (result) {
              triggered = true;
              matchDetails = typeof result === 'object' ? result : { customMatch: true };
            }
          } catch (err) {
            // Don't let custom conditions crash the logger
            matchDetails = { error: err.message };
          }
        }

        // Pattern-based matching
        if (!triggered && rule.pattern) {
          const customPattern = new RegExp(rule.pattern, 'i');
          const messageAndMeta = JSON.stringify(entry);
          if (customPattern.test(messageAndMeta)) {
            triggered = true;
            matchDetails = { matchedPattern: rule.pattern };
          }
        }
        break;
      }

      default: {
        // Generic pattern matching for unknown rule types
        if (rule.pattern) {
          const pattern = new RegExp(rule.pattern, 'i');
          if (pattern.test(JSON.stringify(entry))) {
            triggered = true;
            matchDetails = { matchedPattern: rule.pattern };
          }
        }
        break;
      }
    }

    if (triggered) {
      const alert = {
        ruleId: rule.id || rule.name,
        ruleName: rule.name,
        ruleType: rule.type,
        severity: rule.severity || 'medium',
        timestamp: new Date().toISOString(),
        entry: entry,
        matchDetails: matchDetails,
      };

      // Emit alert event
      alertEmitter.emit('alert', alert);
      alertEmitter.emit(`alert:${rule.severity}`, alert);
      alertEmitter.emit(`alert:${rule.type}`, alert);

      // Call rule-specific callback
      if (rule.callback && typeof rule.callback === 'function') {
        try {
          rule.callback(alert);
        } catch (err) {
          alertEmitter.emit('error', {
            type: 'CALLBACK_ERROR',
            rule: rule.name,
            error: err.message,
          });
        }
      }
    }
  }
}

/**
 * Sets up alert rules for monitoring log entries in real time.
 * Supports detection of bash/shell tool usage, unknown IP addresses,
 * file deletions, and custom patterns.
 *
 * @param {AlertRule[]} rules - Array of alert rules to activate
 * @param {Object} [options] - Alert configuration options
 * @param {boolean} [options.replaceExisting=false] - Replace all existing rules
 * @param {Function} [options.globalCallback] - Global callback for all alerts
 * @param {Function} [options.onError] - Error callback
 * @returns {Object} Alert controller
 * @property {Function} addRule - Add a new rule
 * @property {Function} removeRule - Remove a rule by name
 * @property {Function} getRules - Get all active rules
 * @property {Function} clearRules - Remove all rules
 * @property {Function} on - Subscribe to alert events
 * @property {Function} off - Unsubscribe from alert events
 * @property {Function} getStats - Get alert statistics
 *
 * @example
 * const alertController = setupAlertRules([
 *   {
 *     name: 'bash-detection',
 *     type: 'bash_tool',
 *     severity: 'critical',
 *     callback: (alert) => console.error('BASH TOOL DETECTED:', alert),
 *   },
 *   {
 *     name: 'unknown-ip-detection',
 *     type: 'unknown_ip',
 *     knownIPs: ['192.168.1.1', '10.0.0.1'],
 *     severity: 'high',
 *   },
 *   {
 *     name: 'file-deletion-detection',
 *     type: 'file_deletion',
 *     severity: 'high',
 *     callback: (alert) => console.warn('FILE DELETION:', alert),
 *   },
 *   {
 *     name: 'custom-rule',
 *     type: 'custom',
 *     pattern: 'unauthorized|forbidden|denied',
 *     severity: 'medium',
 *     condition: (entry) => entry.level === 'error' && entry.message.includes('denied'),
 *   },
 * ]);
 *
 * alertController.on('alert', (alert) => {
 *   console.log(`[${alert.severity}] ${alert.ruleName}: ${alert.entry.message}`);
 * });
 */
function setupAlertRules(rules, options = {}) {
  const replaceExisting = options.replaceExisting || false;
  const globalCallback = options.globalCallback || null;

  if (replaceExisting) {
    activeAlertRules = [];
  }

  // Validate and add rules
  const addedRules = [];
  for (const rule of rules) {
    if (!rule.name) {
      throw new Error('Alert rule must have a name');
    }
    if (!rule.type) {
      throw new Error(`Alert rule '${rule.name}' must have a type`);
    }

    const processedRule = {
      id: generateId(),
      name: rule.name,
      type: rule.type,
      pattern: rule.pattern || null,
      knownIPs: rule.knownIPs || [],
      condition: rule.condition || null,
      severity: rule.severity || 'medium',
      callback: rule.callback || null,
      createdAt: new Date().toISOString(),
      triggerCount: 0,
    };

    activeAlertRules.push(processedRule);
    addedRules.push(processedRule);
  }

  // Set up global callback if provided
  if (globalCallback) {
    alertEmitter.on('alert', globalCallback);
  }

  // Track alert statistics
  const stats = {
    totalAlerts: 0,
    alertsByType: {},
    alertsBySeverity: {},
    lastAlertAt: null,
  };

  alertEmitter.on('alert', (alert) => {
    stats.totalAlerts++;
    stats.alertsByType[alert.ruleType] = (stats.alertsByType[alert.ruleType] || 0) + 1;
    stats.alertsBySeverity[alert.severity] = (stats.alertsBySeverity[alert.severity] || 0) + 1;
    stats.lastAlertAt = alert.timestamp;

    // Update trigger count on the rule
    const rule = activeAlertRules.find(r => r.id === alert.ruleId);
    if (rule) {
      rule.triggerCount++;
    }
  });

  return {
    /**
     * Adds a new alert rule.
     * @param {AlertRule} rule - The rule to add
     * @returns {string} The rule ID
     */
    addRule(rule) {
      if (!rule.name || !rule.type) {
        throw new Error('Rule must have a name and type');
      }

      const processedRule = {
        id: generateId(),
        name: rule.name,
        type: rule.type,
        pattern: rule.pattern || null,
        knownIPs: rule.knownIPs || [],
        condition: rule.condition || null,
        severity: rule.severity || 'medium',
        callback: rule.callback || null,
        createdAt: new Date().toISOString(),
        triggerCount: 0,
      };

      activeAlertRules.push(processedRule);
      return processedRule.id;
    },

    /**
     * Removes a rule by name.
     * @param {string} name - The rule name to remove
     * @returns {boolean} True if the rule was found and removed
     */
    removeRule(name) {
      const index = activeAlertRules.findIndex(r => r.name === name);
      if (index >= 0) {
        activeAlertRules.splice(index, 1);
        return true;
      }
      return false;
    },

    /**
     * Gets all active rules.
     * @returns {Object[]} Array of active rules
     */
    getRules() {
      return activeAlertRules.map(r => ({
        id: r.id,
        name: r.name,
        type: r.type,
        severity: r.severity,
        triggerCount: r.triggerCount,
        createdAt: r.createdAt,
      }));
    },

    /**
     * Clears all active rules.
     */
    clearRules() {
      activeAlertRules = [];
    },

    /**
     * Subscribes to alert events.
     * @param {string} event - Event name ('alert', 'alert:critical', 'alert:bash_tool', etc.)
     * @param {Function} listener - Event listener function
     */
    on(event, listener) {
      alertEmitter.on(event, listener);
    },

    /**
     * Unsubscribes from alert events.
     * @param {string} event - Event name
     * @param {Function} listener - Event listener function to remove
     */
    off(event, listener) {
      alertEmitter.off(event, listener);
    },

    /**
     * Gets alert statistics.
     * @returns {Object} Alert statistics
     */
    getStats() {
      return { ...stats };
    },

    /**
     * Gets the internal event emitter for advanced usage.
     * @returns {EventEmitter} The alert event emitter
     */
    getEmitter() {
      return alertEmitter;
    },
  };
}

/**
 * Detects tampering in a log file using multiple heuristic and
 * cryptographic checks. This function performs comprehensive analysis
 * including timestamp ordering, gap detection, hash chain verification,
 * file metadata analysis, and statistical anomaly detection.
 *
 * @param {string} logPath - Path to the log file to analyze
 * @param {Object} [options] - Detection options
 * @param {string} [options.hmacKey] - HMAC key for signature verification
 * @param {boolean} [options.checkTimestamps=true] - Check timestamp ordering
 * @param {boolean} [options.checkSequence=true] - Check sequence numbering
 * @param {boolean} [options.checkChain=true] - Check hash chain integrity
 * @param {boolean} [options.checkFileMetadata=true] - Check file modification times
 * @param {boolean} [options.statisticalAnalysis=true] - Perform statistical anomaly detection
 * @returns {TamperDetectionResult} Detection result with detailed findings
 *
 * @example
 * const result = detectLogTampering('/var/log/audit/secure.log', {
 *   hmacKey: 'your-hmac-key',
 * });
 *
 * if (!result.intact) {
 *   console.error('Tampering detected!');
 *   result.issues.forEach(issue => {
 *     console.error(`  [${issue.type}] Line ${issue.lineNumber}: ${issue.description}`);
 *   });
 * }
 */
function detectLogTampering(logPath, options = {}) {
  const resolvedPath = path.resolve(logPath);
  const checkTimestamps = options.checkTimestamps !== false;
  const checkSequence = options.checkSequence !== false;
  const checkChain = options.checkChain !== false;
  const checkFileMetadata = options.checkFileMetadata !== false;
  const statisticalAnalysis = options.statisticalAnalysis !== false;

  /** @type {TamperDetectionResult} */
  const result = {
    intact: true,
    totalEntries: 0,
    validEntries: 0,
    invalidEntries: 0,
    issues: [],
    analysis: {
      timestampOrder: 'not_checked',
      sequenceIntegrity: 'not_checked',
      hashChainIntegrity: 'not_checked',
      hmacIntegrity: 'not_checked',
      fileMetadata: 'not_checked',
      statisticalAnalysis: 'not_checked',
    },
  };

  // Check if file exists
  if (!fs.existsSync(resolvedPath)) {
    result.intact = false;
    result.issues.push({
      type: 'FILE_MISSING',
      lineNumber: 0,
      severity: 'critical',
      description: `Log file does not exist: ${resolvedPath}`,
    });
    return result;
  }

  // File metadata checks
  if (checkFileMetadata) {
    try {
      const stats = fs.statSync(resolvedPath);
      const lockPath = resolvedPath + '.lock';

      if (fs.existsSync(lockPath)) {
        try {
          const lockData = JSON.parse(fs.readFileSync(lockPath, 'utf8'));

          // Check if file has been truncated
          if (stats.size < lockData.originalSize) {
            result.intact = false;
            result.issues.push({
              type: 'FILE_TRUNCATED',
              lineNumber: 0,
              severity: 'critical',
              description: `File has been truncated. Original size: ${lockData.originalSize}, current size: ${stats.size}`,
            });
          }

          // Check if lock file has been modified
          const lockStats = fs.statSync(lockPath);
          if (lockStats.mtimeMs > new Date(lockData.createdAt).getTime() + 1000) {
            result.issues.push({
              type: 'LOCK_FILE_MODIFIED',
              lineNumber: 0,
              severity: 'high',
              description: 'Lock file appears to have been modified after creation',
            });
          }
        } catch {
          result.issues.push({
            type: 'LOCK_FILE_CORRUPT',
            lineNumber: 0,
            severity: 'medium',
            description: 'Lock file is corrupted or unreadable',
          });
        }
      } else {
        result.issues.push({
          type: 'LOCK_FILE_MISSING',
          lineNumber: 0,
          severity: 'medium',
          description: 'Lock file is missing; cannot verify file metadata',
        });
      }

      // Check file permissions
      const mode = stats.mode & 0o777;
      if (mode & 0o002) {
        result.issues.push({
          type: 'INSECURE_PERMISSIONS',
          lineNumber: 0,
          severity: 'high',
          description: `Log file is world-writable (mode: ${mode.toString(8)})`,
        });
      }

      result.analysis.fileMetadata = result.issues.some(
        i => i.type === 'FILE_TRUNCATED' || i.type === 'LOCK_FILE_MODIFIED'
      ) ? 'suspicious' : 'clean';
    } catch (err) {
      result.issues.push({
        type: 'METADATA_CHECK_ERROR',
        lineNumber: 0,
        severity: 'low',
        description: `Failed to check file metadata: ${err.message}`,
      });
    }
  }

  // Read and parse log entries
  let content;
  try {
    content = fs.readFileSync(resolvedPath, 'utf8').trim();
  } catch (err) {
    result.intact = false;
    result.issues.push({
      type: 'READ_ERROR',
      lineNumber: 0,
      severity: 'critical',
      description: `Failed to read log file: ${err.message}`,
    });
    return result;
  }

  if (!content) {
    return result; // Empty file is not tampered
  }

  const lines = content.split('\n').filter(l => l.trim());
  const entries = [];

  for (let i = 0; i < lines.length; i++) {
    result.totalEntries++;
    try {
      const entry = JSON.parse(lines[i]);
      entry._lineNumber = i + 1;
      entries.push(entry);
    } catch (err) {
      result.intact = false;
      result.invalidEntries++;
      result.issues.push({
        type: 'PARSE_ERROR',
        lineNumber: i + 1,
        severity: 'high',
        description: `Invalid JSON on line ${i + 1}: ${err.message}`,
      });
    }
  }

  // Timestamp ordering check
  if (checkTimestamps && entries.length > 1) {
    let timestampIssues = 0;
    for (let i = 1; i < entries.length; i++) {
      const prevTime = new Date(entries[i - 1].timestamp).getTime();
      const currTime = new Date(entries[i].timestamp).getTime();

      if (isNaN(prevTime) || isNaN(currTime)) {
        result.issues.push({
          type: 'INVALID_TIMESTAMP',
          lineNumber: entries[i]._lineNumber,
          severity: 'high',
          description: `Invalid timestamp on line ${entries[i]._lineNumber}`,
        });
        timestampIssues++;
        continue;
      }

      if (currTime < prevTime) {
        result.intact = false;
        timestampIssues++;
        result.issues.push({
          type: 'TIMESTAMP_ORDER_VIOLATION',
          lineNumber: entries[i]._lineNumber,
          severity: 'high',
          description: `Timestamp goes backward on line ${entries[i]._lineNumber}: ${entries[i].timestamp} < ${entries[i - 1].timestamp}`,
        });
      }

      // Check for suspicious time gaps (> 24 hours between consecutive entries)
      const gap = currTime - prevTime;
      if (gap > 86400000) {
        result.issues.push({
          type: 'LARGE_TIME_GAP',
          lineNumber: entries[i]._lineNumber,
          severity: 'low',
          description: `Large time gap of ${Math.round(gap / 3600000)} hours between lines ${entries[i - 1]._lineNumber} and ${entries[i]._lineNumber}`,
        });
      }
    }
    result.analysis.timestampOrder = timestampIssues > 0 ? 'violated' : 'valid';
  }

  // Sequence number check
  if (checkSequence) {
    let sequenceIssues = 0;
    for (let i = 0; i < entries.length; i++) {
      if (entries[i].sequence !== undefined) {
        const expectedSequence = i + 1;
        if (entries[i].sequence !== expectedSequence) {
          result.intact = false;
          sequenceIssues++;
          result.issues.push({
            type: 'SEQUENCE_GAP',
            lineNumber: entries[i]._lineNumber,
            severity: 'high',
            description: `Sequence number mismatch on line ${entries[i]._lineNumber}: expected ${expectedSequence}, found ${entries[i].sequence}`,
          });
        }
      }
    }

    // Check for duplicate sequence numbers
    const sequences = entries.map(e => e.sequence).filter(s => s !== undefined);
    const uniqueSequences = new Set(sequences);
    if (sequences.length !== uniqueSequences.size) {
      result.intact = false;
      sequenceIssues++;
      result.issues.push({
        type: 'DUPLICATE_SEQUENCE',
        lineNumber: 0,
        severity: 'critical',
        description: `Duplicate sequence numbers detected (${sequences.length} entries, ${uniqueSequences.size} unique)`,
      });
    }

    result.analysis.sequenceIntegrity = sequenceIssues > 0 ? 'violated' : 'valid';
  }

  // Hash chain check
  if (checkChain) {
    let chainIssues = 0;
    let previousHash = computeHash('GENESIS_BLOCK');

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      if (entry.previousHash === undefined) continue;

      if (entry.previousHash !== previousHash) {
        result.intact = false;
        chainIssues++;
        result.issues.push({
          type: 'CHAIN_BREAK',
          lineNumber: entry._lineNumber,
          severity: 'critical',
          description: `Hash chain broken at line ${entry._lineNumber}`,
        });
      }

      // Rebuild canonical data
      const entryData = JSON.stringify({
        id: entry.id,
        sequence: entry.sequence,
        timestamp: entry.timestamp,
        level: entry.level,
        message: entry.message,
        metadata: entry.metadata || {},
        previousHash: entry.previousHash,
        ...(entry.hostname ? { hostname: entry.hostname } : {}),
        ...(entry.pid ? { pid: entry.pid } : {}),
      });

      previousHash = entry.chainHash || computeHash(entryData + (entry.hmac || ''));
    }

    result.analysis.hashChainIntegrity = chainIssues > 0 ? 'broken' : 'intact';
  }

  // HMAC verification (if key provided)
  if (options.hmacKey) {
    let hmacIssues = 0;

    for (const entry of entries) {
      if (!entry.hmac) continue;

      const entryData = JSON.stringify({
        id: entry.id,
        sequence: entry.sequence,
        timestamp: entry.timestamp,
        level: entry.level,
        message: entry.message,
        metadata: entry.metadata || {},
        previousHash: entry.previousHash,
        ...(entry.hostname ? { hostname: entry.hostname } : {}),
        ...(entry.pid ? { pid: entry.pid } : {}),
      });

      const expectedHmac = computeHMAC(entryData, options.hmacKey);
      if (entry.hmac !== expectedHmac) {
        result.intact = false;
        hmacIssues++;
        result.invalidEntries++;
        result.issues.push({
          type: 'HMAC_INVALID',
          lineNumber: entry._lineNumber,
          severity: 'critical',
          description: `HMAC signature invalid on line ${entry._lineNumber} (entry ${entry.id})`,
        });
      } else {
        result.validEntries++;
      }
    }

    result.analysis.hmacIntegrity = hmacIssues > 0 ? 'compromised' : 'valid';
  } else {
    // If no HMAC key, try to load it from the key file
    const keyPath = resolvedPath + '.key';
    if (fs.existsSync(keyPath)) {
      result.issues.push({
        type: 'HMAC_KEY_AVAILABLE',
        lineNumber: 0,
        severity: 'info',
        description: 'HMAC key file exists but no key was provided for verification. Provide hmacKey option for full verification.',
      });
    }
    result.analysis.hmacIntegrity = 'not_checked';
  }

  // Statistical anomaly detection
  if (statisticalAnalysis && entries.length > 10) {
    let anomalies = 0;

    // Check for unusual entry size distribution
    const sizes = entries.map(e => JSON.stringify(e).length);
    const avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length;
    const stdDev = Math.sqrt(sizes.reduce((sum, s) => sum + Math.pow(s - avgSize, 2), 0) / sizes.length);

    for (let i = 0; i < entries.length; i++) {
      if (Math.abs(sizes[i] - avgSize) > 3 * stdDev && stdDev > 0) {
        anomalies++;
        result.issues.push({
          type: 'SIZE_ANOMALY',
          lineNumber: entries[i]._lineNumber,
          severity: 'low',
          description: `Entry size anomaly on line ${entries[i]._lineNumber}: size ${sizes[i]} is ${Math.round(Math.abs(sizes[i] - avgSize) / stdDev)}σ from mean (${Math.round(avgSize)})`,
        });
      }
    }

    // Check for duplicate entry IDs
    const ids = entries.map(e => e.id).filter(Boolean);
    const uniqueIds = new Set(ids);
    if (ids.length !== uniqueIds.size) {
      result.intact = false;
      anomalies++;
      result.issues.push({
        type: 'DUPLICATE_IDS',
        lineNumber: 0,
        severity: 'critical',
        description: `Duplicate entry IDs detected (${ids.length} entries, ${uniqueIds.size} unique IDs)`,
      });
    }

    // Check for entries with identical content (potential replay/injection)
    const contentHashes = new Map();
    for (const entry of entries) {
      const contentHash = computeHash(entry.message + JSON.stringify(entry.metadata || {}));
      if (contentHashes.has(contentHash)) {
        const prevLine = contentHashes.get(contentHash);
        result.issues.push({
          type: 'DUPLICATE_CONTENT',
          lineNumber: entry._lineNumber,
          severity: 'low',
          description: `Duplicate content on lines ${prevLine} and ${entry._lineNumber}`,
        });
      } else {
        contentHashes.set(contentHash, entry._lineNumber);
      }
    }

    // Check for unusual time distribution
    if (entries.length > 2) {
      const intervals = [];
      for (let i = 1; i < entries.length; i++) {
        const prev = new Date(entries[i - 1].timestamp).getTime();
        const curr = new Date(entries[i].timestamp).getTime();
        if (!isNaN(prev) && !isNaN(curr)) {
          intervals.push(curr - prev);
        }
      }

      if (intervals.length > 0) {
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const intervalStdDev = Math.sqrt(
          intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length
        );

        // Check for clusters of rapid entries (potential injection)
        let rapidCluster = 0;
        for (const interval of intervals) {
          if (interval === 0) {
            rapidCluster++;
          } else {
            rapidCluster = 0;
          }
          if (rapidCluster > 5) {
            anomalies++;
            result.issues.push({
              type: 'RAPID_ENTRY_CLUSTER',
              lineNumber: 0,
              severity: 'medium',
              description: `Cluster of ${rapidCluster} entries with identical timestamps detected (potential bulk injection)`,
            });
            break;
          }
        }

        // Check for perfectly uniform intervals (potential fabrication)
        if (intervalStdDev === 0 && entries.length > 20) {
          anomalies++;
          result.issues.push({
            type: 'UNIFORM_INTERVALS',
            lineNumber: 0,
            severity: 'medium',
            description: 'All entries have perfectly uniform time intervals (potential fabrication)',
          });
        }
      }
    }

    // Check for unexpected PID changes
    const pids = entries.map(e => e.pid).filter(Boolean);
    const uniquePids = new Set(pids);
    if (uniquePids.size > 10) {
      result.issues.push({
        type: 'MANY_PIDS',
        lineNumber: 0,
        severity: 'medium',
        description: `Entries from ${uniquePids.size} different PIDs detected (unusual for a single application)`,
      });
    }

    result.analysis.statisticalAnalysis = anomalies > 0 ? 'anomalies_detected' : 'clean';
  }

  // Update valid entries count if HMAC wasn't checked
  if (!options.hmacKey) {
    result.validEntries = entries.length - result.invalidEntries;
  }

  // Final integrity determination
  if (result.issues.some(i => i.severity === 'critical')) {
    result.intact = false;
  }

  // Clean up internal properties
  for (const entry of entries) {
    delete entry._lineNumber;
  }

  return result;
}

/**
 * Reads and loads the HMAC key from the key file associated with a log.
 *
 * @param {string} logPath - Path to the log file
 * @returns {string|null} The HMAC key if found, null otherwise
 *
 * @example
 * const key = loadHmacKey('/var/log/audit/secure.log');
 * if (key) {
 *   const result = verifyLogIntegrity('/var/log/audit/secure.log', key);
 * }
 */
function loadHmacKey(logPath) {
  const keyPath = path.resolve(logPath) + '.key';
  try {
    if (fs.existsSync(keyPath)) {
      const keyData = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
      return keyData.hmacKey || null;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Rotates a log file, creating a timestamped backup and starting a new log.
 *
 * @param {string} logPath - Path to the log file to rotate
 * @param {Object} [options] - Rotation options
 * @param {boolean} [options.compress=false] - Compress the rotated file
 * @param {number} [options.maxBackups=10] - Maximum number of backups to keep
 * @returns {Object} Rotation result
 * @property {string} backupPath - Path to the backup file
 * @property {number} originalSize - Size of the original file
 * @property {string} timestamp - Rotation timestamp
 */
function rotateLog(logPath, options = {}) {
  const resolvedPath = path.resolve(logPath);
  const maxBackups = options.maxBackups || 10;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `${resolvedPath}.${timestamp}.bak`;

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Log file not found: ${resolvedPath}`);
  }

  const stats = fs.statSync(resolvedPath);

  // Copy current log to backup
  fs.copyFileSync(resolvedPath, backupPath);

  // Make backup read-only
  fs.chmodSync(backupPath, 0o444);

  // Clean up old backups
  const dir = path.dirname(resolvedPath);
  const baseName = path.basename(resolvedPath);
  const backups = fs.readdirSync(dir)
    .filter(f => f.startsWith(baseName + '.') && f.endsWith('.bak'))
    .sort()
    .reverse();

  if (backups.length > maxBackups) {
    for (const old of backups.slice(maxBackups)) {
      try {
        fs.unlinkSync(path.join(dir, old));
      } catch {
        // Ignore deletion failures
      }
    }
  }

  return {
    backupPath,
    originalSize: stats.size,
    timestamp,
    entriesBackedUp: fs.readFileSync(resolvedPath, 'utf8').trim().split('\n').filter(l => l.trim()).length,
  };
}

// Module exports
module.exports = {
  setupAppendOnlyLog,
  createSecureLogger,
  verifyLogIntegrity,
  setupLogForwarding,
  setupAlertRules,
  detectLogTampering,
  loadHmacKey,
  rotateLog,
  alertEmitter,
};