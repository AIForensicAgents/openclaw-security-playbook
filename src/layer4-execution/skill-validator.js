/**
 * OpenClaw Skill Plugin Validator
 * A comprehensive module for validating, hashing, scanning, and reporting on OpenClaw skill plugins.
 * @module openclaw-skill-validator
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * @typedef {Object} ValidationResult
 * @property {boolean} valid - Whether the skill passed validation
 * @property {string[]} errors - List of validation errors
 * @property {string[]} warnings - List of validation warnings
 */

/**
 * @typedef {Object} ScanResult
 * @property {boolean} clean - Whether the skill is free of infostealer patterns
 * @property {Object[]} detections - List of detected threats
 * @property {string} detections[].type - Type of threat detected
 * @property {string} detections[].pattern - The pattern that was matched
 * @property {string} detections[].file - The file where the threat was found
 * @property {number} detections[].line - The line number of the detection
 * @property {string} detections[].severity - Severity level: 'critical', 'high', 'medium', 'low'
 * @property {string} detections[].description - Human-readable description of the threat
 */

/**
 * @typedef {Object} WhitelistResult
 * @property {boolean} whitelisted - Whether the skill hash is in the whitelist
 * @property {string} hash - The skill hash that was checked
 * @property {string} [matchedEntry] - The matching whitelist entry name if found
 */

/**
 * @typedef {Object} SkillReport
 * @property {string} skillPath - Absolute path to the skill
 * @property {string} timestamp - ISO 8601 timestamp of report generation
 * @property {string} hash - SHA-256 hash of the skill
 * @property {ValidationResult} validation - Validation results
 * @property {ScanResult} security - Security scan results
 * @property {Object} metadata - Skill metadata extracted from package.json or manifest
 * @property {Object} fileStats - Statistics about the skill files
 * @property {number} fileStats.totalFiles - Total number of files
 * @property {number} fileStats.jsFiles - Number of JavaScript files
 * @property {number} fileStats.totalLines - Total lines of code
 * @property {number} fileStats.totalSize - Total size in bytes
 * @property {string} overallStatus - 'pass', 'warn', or 'fail'
 */

/**
 * Sensitive file system paths that should not be accessed by skill plugins.
 * @constant {string[]}
 * @private
 */
const SENSITIVE_PATHS = [
  // Browser data
  '/cookies',
  '/cookies.sqlite',
  '/Login Data',
  '/Web Data',
  '/Local Storage',
  '/IndexedDB',
  '/Cookies',
  'AppData/Local/Google/Chrome',
  'AppData/Local/Microsoft/Edge',
  'AppData/Roaming/Mozilla/Firefox',
  'AppData/Local/BraveSoftware',
  'AppData/Roaming/Opera Software',
  '.config/google-chrome',
  '.mozilla/firefox',
  'Library/Application Support/Google/Chrome',
  'Library/Application Support/Firefox',
  'Library/Cookies',

  // Crypto wallets
  '.bitcoin',
  '.ethereum',
  '.electrum',
  'wallet.dat',
  '.exodus',
  'exodus',
  'Ethereum/keystore',
  'solana/id.json',
  '.solana',
  'phantomwallet',
  'metamask',

  // Credential stores
  '.ssh/id_rsa',
  '.ssh/id_ed25519',
  '.ssh/id_ecdsa',
  '.ssh/known_hosts',
  '.gnupg',
  '.aws/credentials',
  '.azure',
  '.config/gcloud',
  '.kube/config',
  '.docker/config.json',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.env',
  '.git-credentials',
  'credentials.json',
  'token.json',
  'secrets.json',
  'keychain',
  'Keychain',
  'Login.keychain',

  // System credentials
  '/etc/shadow',
  '/etc/passwd',
  'SAM',
  'SYSTEM',
  'SECURITY',
  'NTDS.dit',

  // Password managers
  '.password-store',
  'KeePass',
  '1Password',
  'LastPass',
  'Bitwarden',
];

/**
 * Dangerous code patterns that indicate potential malicious behavior.
 * @constant {Object[]}
 * @private
 */
const DANGEROUS_PATTERNS = [
  // Dynamic code execution
  {
    regex: /\beval\s*\(/g,
    type: 'dynamic_code_execution',
    severity: 'critical',
    description: 'Use of eval() allows arbitrary code execution',
  },
  {
    regex: /new\s+Function\s*\(/g,
    type: 'dynamic_code_execution',
    severity: 'critical',
    description: 'Use of Function constructor allows arbitrary code execution',
  },
  {
    regex: /\bFunction\s*\(\s*['"]/g,
    type: 'dynamic_code_execution',
    severity: 'critical',
    description: 'Function constructor with string argument allows arbitrary code execution',
  },
  {
    regex: /vm\s*\.\s*(runInNewContext|runInThisContext|createScript|compileFunction)\s*\(/g,
    type: 'dynamic_code_execution',
    severity: 'high',
    description: 'Use of vm module for dynamic code execution',
  },
  {
    regex: /\bsetTimeout\s*\(\s*['"`]/g,
    type: 'dynamic_code_execution',
    severity: 'medium',
    description: 'setTimeout with string argument acts as eval',
  },
  {
    regex: /\bsetInterval\s*\(\s*['"`]/g,
    type: 'dynamic_code_execution',
    severity: 'medium',
    description: 'setInterval with string argument acts as eval',
  },

  // Process spawning
  {
    regex: /require\s*\(\s*['"]child_process['"]\s*\)/g,
    type: 'process_spawning',
    severity: 'critical',
    description: 'Requiring child_process module allows arbitrary command execution',
  },
  {
    regex: /child_process/g,
    type: 'process_spawning',
    severity: 'high',
    description: 'Reference to child_process module detected',
  },
  {
    regex: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(/g,
    type: 'process_spawning',
    severity: 'critical',
    description: 'Process execution function call detected',
  },
  {
    regex: /process\s*\.\s*binding\s*\(/g,
    type: 'process_spawning',
    severity: 'critical',
    description: 'process.binding() can access internal Node.js modules',
  },

  // Network exfiltration
  {
    regex: /require\s*\(\s*['"](http|https|net|dgram|http2)['"]\s*\)/g,
    type: 'network_access',
    severity: 'high',
    description: 'Requiring network module for potential data exfiltration',
  },
  {
    regex: /\b(fetch|axios|request|got|superagent|node-fetch|urllib)\s*\(/g,
    type: 'network_access',
    severity: 'medium',
    description: 'HTTP request function detected - potential data exfiltration',
  },
  {
    regex: /new\s+WebSocket\s*\(/g,
    type: 'network_access',
    severity: 'medium',
    description: 'WebSocket connection detected - potential data exfiltration channel',
  },
  {
    regex: /\.createConnection\s*\(/g,
    type: 'network_access',
    severity: 'high',
    description: 'Raw network connection creation detected',
  },
  {
    regex: /dns\s*\.\s*(resolve|lookup)\s*\(/g,
    type: 'network_access',
    severity: 'medium',
    description: 'DNS lookup detected - potential DNS exfiltration',
  },

  // File system access on sensitive paths
  {
    regex: /require\s*\(\s*['"]fs['"]\s*\)/g,
    type: 'filesystem_access',
    severity: 'medium',
    description: 'Requiring fs module - check for sensitive path access',
  },
  {
    regex: /require\s*\(\s*['"]fs\/promises['"]\s*\)/g,
    type: 'filesystem_access',
    severity: 'medium',
    description: 'Requiring fs/promises module - check for sensitive path access',
  },

  // Obfuscation techniques
  {
    regex: /Buffer\s*\.\s*from\s*\(\s*['"][A-Za-z0-9+/=]+['"]\s*,\s*['"]base64['"]\s*\)/g,
    type: 'obfuscation',
    severity: 'high',
    description: 'Base64 encoded string in Buffer - potential obfuscated payload',
  },
  {
    regex: /atob\s*\(/g,
    type: 'obfuscation',
    severity: 'medium',
    description: 'Base64 decoding detected - potential obfuscated payload',
  },
  {
    regex: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/g,
    type: 'obfuscation',
    severity: 'high',
    description: 'Long hex escape sequence detected - potential obfuscated code',
  },
  {
    regex: /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}/g,
    type: 'obfuscation',
    severity: 'high',
    description: 'Long unicode escape sequence detected - potential obfuscated code',
  },
  {
    regex: /String\s*\.\s*fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/g,
    type: 'obfuscation',
    severity: 'high',
    description: 'String.fromCharCode with many arguments - potential obfuscated string',
  },

  // Environment/credential harvesting
  {
    regex: /process\s*\.\s*env/g,
    type: 'credential_harvesting',
    severity: 'medium',
    description: 'Accessing process.env - may harvest environment credentials',
  },
  {
    regex: /os\s*\.\s*(homedir|userInfo|hostname|platform)\s*\(/g,
    type: 'reconnaissance',
    severity: 'low',
    description: 'System information gathering detected',
  },

  // Prototype pollution
  {
    regex: /__proto__/g,
    type: 'prototype_pollution',
    severity: 'high',
    description: 'Reference to __proto__ - potential prototype pollution',
  },
  {
    regex: /constructor\s*\[\s*['"]prototype['"]\s*\]/g,
    type: 'prototype_pollution',
    severity: 'high',
    description: 'Prototype access via constructor - potential prototype pollution',
  },
];

/**
 * Infostealer-specific patterns for cookie theft, wallet key extraction, and credential harvesting.
 * @constant {Object[]}
 * @private
 */
const INFOSTEALER_PATTERNS = [
  // Cookie theft
  {
    regex: /cookie/gi,
    type: 'cookie_theft',
    severity: 'high',
    description: 'Reference to cookies detected',
    contextRequired: true,
  },
  {
    regex: /document\s*\.\s*cookie/g,
    type: 'cookie_theft',
    severity: 'critical',
    description: 'Direct access to document.cookie',
    contextRequired: false,
  },
  {
    regex: /setCookie|getCookie|parseCookie|cookie[_-]?jar|cookie[_-]?store/gi,
    type: 'cookie_theft',
    severity: 'high',
    description: 'Cookie manipulation function detected',
    contextRequired: false,
  },
  {
    regex: /Cookies\s*\.sqlite|cookies\s*\.db/gi,
    type: 'cookie_theft',
    severity: 'critical',
    description: 'Browser cookie database file reference',
    contextRequired: false,
  },
  {
    regex: /chrome.*cookies|firefox.*cookies|safari.*cookies/gi,
    type: 'cookie_theft',
    severity: 'critical',
    description: 'Browser-specific cookie store access',
    contextRequired: false,
  },
  {
    regex: /session[_-]?(id|token|key)|PHPSESSID|JSESSIONID|connect\.sid/gi,
    type: 'cookie_theft',
    severity: 'high',
    description: 'Session token/identifier reference detected',
    contextRequired: false,
  },

  // Wallet key extraction
  {
    regex: /wallet\s*\.\s*dat/gi,
    type: 'wallet_theft',
    severity: 'critical',
    description: 'Bitcoin wallet.dat file reference',
    contextRequired: false,
  },
  {
    regex: /keystore|key\s*store/gi,
    type: 'wallet_theft',
    severity: 'high',
    description: 'Keystore reference - potential wallet key extraction',
    contextRequired: true,
  },
  {
    regex: /private\s*key|privkey|priv_key|secret\s*key|mnemonic|seed\s*phrase|recovery\s*phrase/gi,
    type: 'wallet_theft',
    severity: 'critical',
    description: 'Cryptocurrency private key/seed phrase reference',
    contextRequired: false,
  },
  {
    regex: /solana.*id\.json|\.solana/gi,
    type: 'wallet_theft',
    severity: 'critical',
    description: 'Solana wallet key file reference',
    contextRequired: false,
  },
  {
    regex: /metamask|phantom|exodus|electrum|ledger|trezor/gi,
    type: 'wallet_theft',
    severity: 'high',
    description: 'Cryptocurrency wallet application reference',
    contextRequired: true,
  },
  {
    regex: /ethereum.*keystore|\.ethereum/gi,
    type: 'wallet_theft',
    severity: 'critical',
    description: 'Ethereum keystore directory reference',
    contextRequired: false,
  },
  {
    regex: /BIP39|BIP44|BIP32/gi,
    type: 'wallet_theft',
    severity: 'high',
    description: 'Cryptocurrency key derivation standard reference',
    contextRequired: true,
  },

  // Credential harvesting
  {
    regex: /Login\s*Data|login.*data/gi,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'Browser Login Data file reference (stored passwords)',
    contextRequired: false,
  },
  {
    regex: /chrome.*password|firefox.*password|password.*store/gi,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'Browser password store reference',
    contextRequired: false,
  },
  {
    regex: /\.ssh\/id_rsa|\.ssh\/id_ed25519|\.ssh\/id_ecdsa/g,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'SSH private key file path reference',
    contextRequired: false,
  },
  {
    regex: /\.aws\/credentials|AWS_ACCESS_KEY|AWS_SECRET/gi,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'AWS credential file/variable reference',
    contextRequired: false,
  },
  {
    regex: /\.env\b|dotenv|DOTENV/g,
    type: 'credential_harvesting',
    severity: 'high',
    description: 'Environment file reference - may contain secrets',
    contextRequired: true,
  },
  {
    regex: /\.npmrc|\.pypirc|\.docker\/config|\.kube\/config/g,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'Package/container registry credential file reference',
    contextRequired: false,
  },
  {
    regex: /keychain|keyring|credential\s*manager|vault/gi,
    type: 'credential_harvesting',
    severity: 'high',
    description: 'System credential store reference',
    contextRequired: true,
  },
  {
    regex: /password|passwd|pwd/gi,
    type: 'credential_harvesting',
    severity: 'low',
    description: 'Password-related term detected',
    contextRequired: true,
  },
  {
    regex: /\/etc\/shadow|\/etc\/passwd|SAM|NTDS\.dit/g,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'System password/authentication database reference',
    contextRequired: false,
  },
  {
    regex: /git-credentials|\.gitconfig.*credential/g,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'Git credential store reference',
    contextRequired: false,
  },
  {
    regex: /1password|lastpass|keepass|bitwarden/gi,
    type: 'credential_harvesting',
    severity: 'critical',
    description: 'Password manager database reference',
    contextRequired: false,
  },
];

/**
 * Recursively collects all files within a directory.
 * @private
 * @param {string} dirPath - The directory to scan
 * @param {string[]} [fileList=[]] - Accumulated file list
 * @returns {string[]} Array of absolute file paths
 */
function collectFiles(dirPath, fileList = []) {
  const resolvedDir = path.resolve(dirPath);

  try {
    const stat = fs.statSync(resolvedDir);
    if (stat.isFile()) {
      fileList.push(resolvedDir);
      return fileList;
    }

    if (!stat.isDirectory()) {
      return fileList;
    }
  } catch (err) {
    return fileList;
  }

  try {
    const entries = fs.readdirSync(resolvedDir);
    for (const entry of entries) {
      // Skip common non-essential directories
      if (entry === 'node_modules' || entry === '.git' || entry === '.svn') {
        continue;
      }
      const fullPath = path.join(resolvedDir, entry);
      try {
        const entryStat = fs.statSync(fullPath);
        if (entryStat.isDirectory()) {
          collectFiles(fullPath, fileList);
        } else if (entryStat.isFile()) {
          fileList.push(fullPath);
        }
      } catch (err) {
        // Skip files that can't be read
      }
    }
  } catch (err) {
    // Skip directories that can't be read
  }

  return fileList;
}

/**
 * Collects all JavaScript/JSON files for analysis.
 * @private
 * @param {string} skillPath - Path to the skill directory or file
 * @returns {string[]} Array of JS/JSON file paths
 */
function collectAnalyzableFiles(skillPath) {
  const allFiles = collectFiles(skillPath);
  const analyzableExtensions = new Set([
    '.js', '.mjs', '.cjs', '.jsx',
    '.ts', '.tsx', '.mts', '.cts',
    '.json', '.jsonc',
  ]);

  return allFiles.filter((f) => {
    const ext = path.extname(f).toLowerCase();
    return analyzableExtensions.has(ext);
  });
}

/**
 * Checks if a file path contains references to sensitive file system locations.
 * @private
 * @param {string} content - File content to scan
 * @returns {Object[]} Array of sensitive path detections
 */
function checkSensitivePathAccess(content) {
  const detections = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const sensitivePath of SENSITIVE_PATHS) {
      if (line.includes(sensitivePath)) {
        // Check if it's in a string context (likely a path being accessed)
        const inString = /['"`].*/.test(line) || /readFile|readdir|access|open|stat|createReadStream/.test(line);
        if (inString) {
          detections.push({
            type: 'sensitive_path_access',
            pattern: sensitivePath,
            line: i + 1,
            severity: 'critical',
            description: `Access to sensitive path detected: ${sensitivePath}`,
            lineContent: line.trim(),
          });
        }
      }
    }
  }

  return detections;
}

/**
 * Checks if fs module usage targets sensitive paths by analyzing the surrounding context.
 * @private
 * @param {string} content - File content to scan
 * @returns {Object[]} Array of detections for fs usage on sensitive paths
 */
function checkFsSensitiveUsage(content) {
  const detections = [];
  const lines = content.split('\n');

  const fsMethodRegex = /\b(readFile|readFileSync|readdir|readdirSync|createReadStream|open|openSync|access|accessSync|stat|statSync|copyFile|copyFileSync|rename|renameSync)\s*\(/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let match;
    fsMethodRegex.lastIndex = 0;

    while ((match = fsMethodRegex.exec(line)) !== null) {
      // Check surrounding context (current line plus a few lines ahead) for sensitive paths
      const contextWindow = lines.slice(i, Math.min(i + 5, lines.length)).join('\n');
      for (const sensitivePath of SENSITIVE_PATHS) {
        if (contextWindow.includes(sensitivePath)) {
          detections.push({
            type: 'fs_sensitive_access',
            pattern: `${match[1]}() targeting ${sensitivePath}`,
            line: i + 1,
            severity: 'critical',
            description: `File system operation '${match[1]}' used near sensitive path '${sensitivePath}'`,
            lineContent: line.trim(),
          });
        }
      }
    }
  }

  return detections;
}

/**
 * Validates an OpenClaw skill plugin for structural integrity and security concerns.
 *
 * Checks include:
 * - Directory/file existence and readability
 * - Presence of required skill manifest or package.json
 * - Valid entry point
 * - Dangerous code patterns (eval, Function constructor, child_process, etc.)
 * - File system access to sensitive paths
 * - Obfuscation techniques
 *
 * @param {string} skillPath - Absolute or relative path to the skill directory or main file
 * @returns {ValidationResult} The validation result object
 * @throws {Error} If skillPath is not a string or is empty
 *
 * @example
 * const { validateSkill } = require('./openclaw-skill-validator');
 * const result = validateSkill('./my-skill');
 * if (!result.valid) {
 *   console.error('Validation errors:', result.errors);
 * }
 */
function validateSkill(skillPath) {
  if (typeof skillPath !== 'string' || skillPath.trim() === '') {
    throw new Error('skillPath must be a non-empty string');
  }

  const resolvedPath = path.resolve(skillPath);
  const errors = [];
  const warnings = [];

  // Check existence
  try {
    fs.accessSync(resolvedPath, fs.constants.R_OK);
  } catch (err) {
    return {
      valid: false,
      errors: [`Skill path does not exist or is not readable: ${resolvedPath}`],
      warnings: [],
    };
  }

  const stat = fs.statSync(resolvedPath);
  const isDirectory = stat.isDirectory();

  // If directory, check for manifest/package.json
  if (isDirectory) {
    const packageJsonPath = path.join(resolvedPath, 'package.json');
    const manifestPath = path.join(resolvedPath, 'skill.json');
    const hasPackageJson = fs.existsSync(packageJsonPath);
    const hasManifest = fs.existsSync(manifestPath);

    if (!hasPackageJson && !hasManifest) {
      warnings.push('No package.json or skill.json manifest found in skill directory');
    }

    // Validate package.json if present
    if (hasPackageJson) {
      try {
        const packageContent = fs.readFileSync(packageJsonPath, 'utf-8');
        const packageJson = JSON.parse(packageContent);

        if (!packageJson.name) {
          errors.push('package.json missing "name" field');
        }

        if (!packageJson.version) {
          errors.push('package.json missing "version" field');
        }

        if (!packageJson.main) {
          warnings.push('package.json missing "main" entry point field');
        } else {
          const entryPoint = path.join(resolvedPath, packageJson.main);
          if (!fs.existsSync(entryPoint)) {
            errors.push(`Entry point "${packageJson.main}" specified in package.json does not exist`);
          }
        }

        // Check for suspicious dependencies
        const allDeps = {
          ...packageJson.dependencies,
          ...packageJson.devDependencies,
        };

        const suspiciousDeps = [
          'child_process', 'node-pty', 'node-cmd', 'shelljs',
          'puppeteer', 'playwright', 'selenium-webdriver',
        ];

        for (const dep of Object.keys(allDeps || {})) {
          if (suspiciousDeps.includes(dep)) {
            warnings.push(`Suspicious dependency found: "${dep}"`);
          }
        }
      } catch (parseErr) {
        errors.push(`Invalid package.json: ${parseErr.message}`);
      }
    }

    // Validate skill.json manifest if present
    if (hasManifest) {
      try {
        const manifestContent = fs.readFileSync(manifestPath, 'utf-8');
        const manifest = JSON.parse(manifestContent);

        if (!manifest.id) {
          errors.push('skill.json missing "id" field');
        }

        if (!manifest.name) {
          errors.push('skill.json missing "name" field');
        }

        if (!manifest.version) {
          errors.push('skill.json missing "version" field');
        }

        if (!manifest.entry) {
          warnings.push('skill.json missing "entry" field');
        } else {
          const entryPoint = path.join(resolvedPath, manifest.entry);
          if (!fs.existsSync(entryPoint)) {
            errors.push(`Entry point "${manifest.entry}" specified in skill.json does not exist`);
          }
        }

        if (manifest.permissions && Array.isArray(manifest.permissions)) {
          const dangerousPerms = ['filesystem', 'network', 'process', 'eval'];
          for (const perm of manifest.permissions) {
            if (dangerousPerms.includes(perm)) {
              warnings.push(`Skill requests dangerous permission: "${perm}"`);
            }
          }
        }
      } catch (parseErr) {
        errors.push(`Invalid skill.json: ${parseErr.message}`);
      }
    }
  }

  // Scan all analyzable files for dangerous patterns
  const analyzableFiles = collectAnalyzableFiles(resolvedPath);

  if (analyzableFiles.length === 0) {
    errors.push('No analyzable files (JS/JSON) found in skill');
    return { valid: false, errors, warnings };
  }

  for (const filePath of analyzableFiles) {
    // Skip JSON files for pattern scanning (except for sensitive data patterns)
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.json' || ext === '.jsonc') {
      continue;
    }

    let content;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch (err) {
      warnings.push(`Could not read file for analysis: ${filePath}`);
      continue;
    }

    const relativePath = path.relative(resolvedPath, filePath) || path.basename(filePath);

    // Check dangerous patterns
    for (const pattern of DANGEROUS_PATTERNS) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      const lines = content.split('\n');

      while ((match = regex.exec(content)) !== null) {
        // Calculate line number
        const upToMatch = content.substring(0, match.index);
        const lineNumber = upToMatch.split('\n').length;

        const message = `[${pattern.severity.toUpperCase()}] ${pattern.description} in ${relativePath}:${lineNumber}`;

        if (pattern.severity === 'critical') {
          errors.push(message);
        } else if (pattern.severity === 'high') {
          errors.push(message);
        } else {
          warnings.push(message);
        }
      }
    }

    // Check for sensitive path access
    const sensitiveDetections = checkSensitivePathAccess(content);
    for (const detection of sensitiveDetections) {
      errors.push(
        `[${detection.severity.toUpperCase()}] ${detection.description} in ${relativePath}:${detection.line}`
      );
    }

    // Check for fs operations targeting sensitive paths
    const fsDetections = checkFsSensitiveUsage(content);
    for (const detection of fsDetections) {
      errors.push(
        `[${detection.severity.toUpperCase()}] ${detection.description} in ${relativePath}:${detection.line}`
      );
    }

    // Check for excessively long lines (potential obfuscation)
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > 5000) {
        warnings.push(
          `Excessively long line (${lines[i].length} chars) in ${relativePath}:${i + 1} - possible obfuscation`
        );
      }
    }

    // Check for minified code without source maps
    const avgLineLength = content.length / Math.max(lines.length, 1);
    if (avgLineLength > 500 && lines.length < 10) {
      warnings.push(
        `File appears to be minified/obfuscated without source maps: ${relativePath}`
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Computes a SHA-256 hash of the entire skill plugin contents.
 *
 * For directories, all files are sorted by relative path and their contents
 * are concatenated with path separators before hashing, ensuring deterministic results.
 * The node_modules and .git directories are excluded from hashing.
 *
 * @param {string} skillPath - Absolute or relative path to the skill directory or file
 * @returns {string} The SHA-256 hex digest of the skill contents
 * @throws {Error} If skillPath is not a string, is empty, or doesn't exist
 *
 * @example
 * const { computeSkillHash } = require('./openclaw-skill-validator');
 * const hash = computeSkillHash('./my-skill');
 * console.log(`Skill hash: ${hash}`);
 */
function computeSkillHash(skillPath) {
  if (typeof skillPath !== 'string' || skillPath.trim() === '') {
    throw new Error('skillPath must be a non-empty string');
  }

  const resolvedPath = path.resolve(skillPath);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Skill path does not exist: ${resolvedPath}`);
  }

  const hash = crypto.createHash('sha256');
  const stat = fs.statSync(resolvedPath);

  if (stat.isFile()) {
    const content = fs.readFileSync(resolvedPath);
    hash.update(content);
    return hash.digest('hex');
  }

  // For directories, collect all files, sort them, and hash deterministically
  const allFiles = collectFiles(resolvedPath);

  // Sort by relative path for deterministic ordering
  const fileEntries = allFiles
    .map((f) => ({
      relativePath: path.relative(resolvedPath, f),
      absolutePath: f,
    }))
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath));

  for (const entry of fileEntries) {
    // Include the relative path as a separator to ensure different directory
    // structures produce different hashes
    hash.update(`\x00FILE:${entry.relativePath}\x00`);
    try {
      const content = fs.readFileSync(entry.absolutePath);
      hash.update(content);
    } catch (err) {
      // Include a marker for unreadable files so they still affect the hash
      hash.update(`\x00UNREADABLE\x00`);
    }
  }

  return hash.digest('hex');
}

/**
 * Checks whether a given skill hash is present in a whitelist file.
 *
 * The whitelist file should be a JSON file with the following structure:
 *