/**
 * @module llm-data-scrubber
 * @description A comprehensive Node.js CommonJS module for scrubbing sensitive data
 * before sending to cloud LLM APIs. Handles environment variables, credentials,
 * PII, and provides proxy and reporting functionality.
 */

'use strict';

const http = require('http');
const https = require('https');
const url = require('url');

// ============================================================================
// Pattern Definitions
// ============================================================================

/**
 * @typedef {Object} ScrubPattern
 * @property {string} name - Human-readable name of the pattern
 * @property {RegExp} pattern - Regular expression to match sensitive data
 * @property {string} replacement - Replacement string
 * @property {string} category - Category of the sensitive data
 */

/** @type {ScrubPattern[]} */
const ENV_VAR_PATTERNS = [
  {
    name: 'Generic Environment Variable Assignment',
    pattern: /(?:^|\n|;)\s*(?:export\s+)?([A-Z_][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS|_PWD|_CREDENTIAL|_AUTH|_API_KEY|_APIKEY|_ACCESS_KEY|_PRIVATE_KEY))\s*=\s*['"]?([^\s'";\n]+)['"]?/gi,
    replacement: '$1=[ENV_VAR_SCRUBBED]',
    category: 'environment_variable'
  },
  {
    name: 'Inline Environment Variable Reference',
    pattern: /\$\{?([A-Z_][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS|_PWD|_CREDENTIAL|_AUTH|_API_KEY|_APIKEY))\}?/gi,
    replacement: '${$1_SCRUBBED}',
    category: 'environment_variable'
  },
  {
    name: 'dotenv style assignments',
    pattern: /^((?:DB|DATABASE|MONGO|REDIS|MYSQL|POSTGRES|PG|SMTP|MAIL|EMAIL|AWS|GCP|AZURE|GITHUB|GITLAB|SLACK|STRIPE|TWILIO|SENDGRID|FIREBASE|ALGOLIA|SENTRY|DATADOG|NEW_RELIC|AUTH0|OKTA|JWT|SESSION|COOKIE|ENCRYPTION|HASH|SIGNING|API|APP|SERVICE|INTERNAL)[A-Z0-9_]*(?:_URL|_URI|_DSN|_CONNECTION|_STRING|_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS))\s*=\s*(.+)$/gim,
    replacement: '$1=[ENV_VAR_SCRUBBED]',
    category: 'environment_variable'
  },
  {
    name: 'process.env references with values',
    pattern: /process\.env\.([A-Z_][A-Z0-9_]*)\s*(?:=|\|\|)\s*['"]([^'"]+)['"]/gi,
    replacement: 'process.env.$1 = "[ENV_VAR_SCRUBBED]"',
    category: 'environment_variable'
  }
];

/** @type {ScrubPattern[]} */
const CREDENTIAL_PATTERNS = [
  // AWS Credentials
  {
    name: 'AWS Access Key ID',
    pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
    replacement: '[AWS_ACCESS_KEY_SCRUBBED]',
    category: 'aws_credential'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretaccesskey)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    replacement: 'aws_secret_access_key=[AWS_SECRET_KEY_SCRUBBED]',
    category: 'aws_credential'
  },
  {
    name: 'AWS Session Token',
    pattern: /(?:aws_session_token|sessiontoken)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?/gi,
    replacement: 'aws_session_token=[AWS_SESSION_TOKEN_SCRUBBED]',
    category: 'aws_credential'
  },
  {
    name: 'AWS ARN',
    pattern: /arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+/g,
    replacement: '[AWS_ARN_SCRUBBED]',
    category: 'aws_credential'
  },
  {
    name: 'AWS MWS Key',
    pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    replacement: '[AWS_MWS_KEY_SCRUBBED]',
    category: 'aws_credential'
  },

  // GCP Credentials
  {
    name: 'GCP API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    replacement: '[GCP_API_KEY_SCRUBBED]',
    category: 'gcp_credential'
  },
  {
    name: 'GCP Service Account Email',
    pattern: /[a-zA-Z0-9\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com/g,
    replacement: '[GCP_SERVICE_ACCOUNT_SCRUBBED]',
    category: 'gcp_credential'
  },
  {
    name: 'GCP OAuth Token',
    pattern: /ya29\.[0-9A-Za-z\-_]+/g,
    replacement: '[GCP_OAUTH_TOKEN_SCRUBBED]',
    category: 'gcp_credential'
  },
  {
    name: 'GCP Private Key',
    pattern: /-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----[\s\S]*?-----END\s(?:RSA\s)?PRIVATE\sKEY-----/g,
    replacement: '[PRIVATE_KEY_SCRUBBED]',
    category: 'gcp_credential'
  },
  {
    name: 'GCP Private Key ID pattern',
    pattern: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/gi,
    replacement: '"private_key_id": "[GCP_PRIVATE_KEY_ID_SCRUBBED]"',
    category: 'gcp_credential'
  },
  {
    name: 'GCP Client ID',
    pattern: /\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com/g,
    replacement: '[GCP_CLIENT_ID_SCRUBBED]',
    category: 'gcp_credential'
  },

  // GitHub Tokens
  {
    name: 'GitHub Personal Access Token (Classic)',
    pattern: /ghp_[0-9A-Za-z]{36}/g,
    replacement: '[GITHUB_PAT_SCRUBBED]',
    category: 'github_credential'
  },
  {
    name: 'GitHub Fine-grained Token',
    pattern: /github_pat_[0-9A-Za-z_]{82}/g,
    replacement: '[GITHUB_FINE_GRAINED_TOKEN_SCRUBBED]',
    category: 'github_credential'
  },
  {
    name: 'GitHub OAuth Access Token',
    pattern: /gho_[0-9A-Za-z]{36}/g,
    replacement: '[GITHUB_OAUTH_TOKEN_SCRUBBED]',
    category: 'github_credential'
  },
  {
    name: 'GitHub User-to-Server Token',
    pattern: /ghu_[0-9A-Za-z]{36}/g,
    replacement: '[GITHUB_U2S_TOKEN_SCRUBBED]',
    category: 'github_credential'
  },
  {
    name: 'GitHub Server-to-Server Token',
    pattern: /ghs_[0-9A-Za-z]{36}/g,
    replacement: '[GITHUB_S2S_TOKEN_SCRUBBED]',
    category: 'github_credential'
  },
  {
    name: 'GitHub Refresh Token',
    pattern: /ghr_[0-9A-Za-z]{36}/g,
    replacement: '[GITHUB_REFRESH_TOKEN_SCRUBBED]',
    category: 'github_credential'
  },

  // Database Connection Strings
  {
    name: 'MongoDB Connection String',
    pattern: /mongodb(?:\+srv)?:\/\/([^:]+):([^@]+)@[^\s'"]+/gi,
    replacement: 'mongodb://[DB_CREDENTIALS_SCRUBBED]@[DB_HOST_SCRUBBED]',
    category: 'database_credential'
  },
  {
    name: 'PostgreSQL Connection String',
    pattern: /postgres(?:ql)?:\/\/([^:]+):([^@]+)@[^\s'"]+/gi,
    replacement: 'postgresql://[DB_CREDENTIALS_SCRUBBED]@[DB_HOST_SCRUBBED]',
    category: 'database_credential'
  },
  {
    name: 'MySQL Connection String',
    pattern: /mysql:\/\/([^:]+):([^@]+)@[^\s'"]+/gi,
    replacement: 'mysql://[DB_CREDENTIALS_SCRUBBED]@[DB_HOST_SCRUBBED]',
    category: 'database_credential'
  },
  {
    name: 'Redis Connection String',
    pattern: /redis(?:s)?:\/\/(?:([^:]+):)?([^@]+)@[^\s'"]+/gi,
    replacement: 'redis://[DB_CREDENTIALS_SCRUBBED]@[DB_HOST_SCRUBBED]',
    category: 'database_credential'
  },
  {
    name: 'MSSQL Connection String',
    pattern: /Server\s*=\s*[^;]+;\s*Database\s*=\s*[^;]+;\s*(?:User\s*Id|Uid)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^;'"]+/gi,
    replacement: '[MSSQL_CONNECTION_STRING_SCRUBBED]',
    category: 'database_credential'
  },
  {
    name: 'JDBC Connection String',
    pattern: /jdbc:[a-z]+:\/\/[^\s'"]*(?:password|passwd|pwd)\s*=\s*[^\s&'"]+/gi,
    replacement: '[JDBC_CONNECTION_SCRUBBED]',
    category: 'database_credential'
  },

  // Generic API Keys and Tokens
  {
    name: 'Generic API Key in Header',
    pattern: /(?:x-api-key|api-key|apikey|api_key|authorization)\s*[=:]\s*['"]?(?:Bearer\s+)?([A-Za-z0-9\-_.~+/]{20,})['"]?/gi,
    replacement: '$1=[API_KEY_SCRUBBED]',
    category: 'api_credential'
  },
  {
    name: 'Bearer Token',
    pattern: /Bearer\s+[A-Za-z0-9\-_.~+/]{20,}/gi,
    replacement: 'Bearer [BEARER_TOKEN_SCRUBBED]',
    category: 'api_credential'
  },
  {
    name: 'Basic Auth Header',
    pattern: /Basic\s+[A-Za-z0-9+/=]{10,}/gi,
    replacement: 'Basic [BASIC_AUTH_SCRUBBED]',
    category: 'api_credential'
  },

  // Other Service Tokens
  {
    name: 'Slack Token',
    pattern: /xox[bpaosr]-[0-9A-Za-z\-]{10,}/g,
    replacement: '[SLACK_TOKEN_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    replacement: '[SLACK_WEBHOOK_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'Stripe API Key',
    pattern: /(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{24,}/g,
    replacement: '[STRIPE_KEY_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'Twilio API Key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    replacement: '[TWILIO_API_KEY_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[0-9A-Za-z\-_.]{22}\.[0-9A-Za-z\-_.]{43}/g,
    replacement: '[SENDGRID_API_KEY_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'Heroku API Key',
    pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    replacement: '[UUID_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'NPM Token',
    pattern: /npm_[0-9A-Za-z]{36}/g,
    replacement: '[NPM_TOKEN_SCRUBBED]',
    category: 'service_credential'
  },
  {
    name: 'Azure Subscription Key',
    pattern: /[0-9a-f]{32}/gi,
    // This is too broad on its own; we only match it in specific contexts
    replacement: '[AZURE_KEY_SCRUBBED]',
    category: 'service_credential',
    contextRequired: true // Flag to indicate this needs context
  },
  {
    name: 'SSH Private Key',
    pattern: /-----BEGIN\s(?:OPENSSH|DSA|EC|PGP)\s(?:PRIVATE\s)?KEY-----[\s\S]*?-----END\s(?:OPENSSH|DSA|EC|PGP)\s(?:PRIVATE\s)?KEY-----/g,
    replacement: '[SSH_PRIVATE_KEY_SCRUBBED]',
    category: 'ssh_credential'
  },
  {
    name: 'Certificate',
    pattern: /-----BEGIN\sCERTIFICATE-----[\s\S]*?-----END\sCERTIFICATE-----/g,
    replacement: '[CERTIFICATE_SCRUBBED]',
    category: 'certificate'
  },
  {
    name: 'Password in URL',
    pattern: /:\/\/([^:]+):([^@]{3,})@/g,
    replacement: '://[USER_SCRUBBED]:[PASSWORD_SCRUBBED]@',
    category: 'url_credential'
  },
  {
    name: 'Generic secret/password/token value assignment',
    pattern: /(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|client[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*['"]([^'"]{8,})['"]|(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|client[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*([^\s,;'"}{]{8,})/gi,
    replacement: '[CREDENTIAL_KEY]=[CREDENTIAL_VALUE_SCRUBBED]',
    category: 'generic_credential'
  }
];

/** @type {ScrubPattern[]} */
const PII_PATTERNS = [
  // SSN Patterns
  {
    name: 'US Social Security Number (formatted)',
    pattern: /\b(\d{3})-(\d{2})-(\d{4})\b/g,
    replacement: '[SSN_SCRUBBED]',
    category: 'ssn',
    validator: (match) => {
      const [, area, group, serial] = match.match(/(\d{3})-(\d{2})-(\d{4})/) || [];
      if (!area || !group || !serial) return false;
      if (area === '000' || area === '666' || parseInt(area) >= 900) return false;
      if (group === '00') return false;
      if (serial === '0000') return false;
      return true;
    }
  },
  {
    name: 'US Social Security Number (unformatted)',
    pattern: /\b(\d{3})(\d{2})(\d{4})\b/g,
    replacement: '[SSN_SCRUBBED]',
    category: 'ssn',
    validator: (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length !== 9) return false;
      const area = digits.substring(0, 3);
      const group = digits.substring(3, 5);
      const serial = digits.substring(5, 9);
      if (area === '000' || area === '666' || parseInt(area) >= 900) return false;
      if (group === '00') return false;
      if (serial === '0000') return false;
      return true;
    }
  },
  {
    name: 'SSN with label',
    pattern: /(?:ssn|social\s*security(?:\s*(?:number|num|no|#))?)\s*[=:]\s*['"]?\d{3}[- ]?\d{2}[- ]?\d{4}['"]?/gi,
    replacement: '[SSN_FIELD_SCRUBBED]',
    category: 'ssn'
  },

  // Credit Card Patterns
  {
    name: 'Visa Card',
    pattern: /\b4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    replacement: '[VISA_CARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'Mastercard',
    pattern: /\b5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    replacement: '[MASTERCARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'Mastercard (2-series)',
    pattern: /\b2(?:2[2-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    replacement: '[MASTERCARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'American Express',
    pattern: /\b3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}\b/g,
    replacement: '[AMEX_CARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'Discover Card',
    pattern: /\b6(?:011|5[0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/g,
    replacement: '[DISCOVER_CARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'Diners Club',
    pattern: /\b3(?:0[0-5]|[68][0-9])[0-9][- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{2}\b/g,
    replacement: '[DINERS_CARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'JCB Card',
    pattern: /\b(?:2131|1800|35\d{3})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    replacement: '[JCB_CARD_SCRUBBED]',
    category: 'credit_card',
    validator: luhnCheck
  },
  {
    name: 'Credit Card with label',
    pattern: /(?:credit\s*card|card\s*(?:number|num|no|#)|cc\s*(?:number|num|no|#)?)\s*[=:]\s*['"]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}['"]?/gi,
    replacement: '[CREDIT_CARD_FIELD_SCRUBBED]',
    category: 'credit_card'
  },
  {
    name: 'CVV/CVC',
    pattern: /(?:cvv|cvc|cvv2|cvc2|security\s*code)\s*[=:]\s*['"]?\d{3,4}['"]?/gi,
    replacement: '[CVV_SCRUBBED]',
    category: 'credit_card'
  },

  // Email Addresses
  {
    name: 'Email Address',
    pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    replacement: '[EMAIL_SCRUBBED]',
    category: 'email'
  },

  // Phone Numbers
  {
    name: 'US Phone Number',
    pattern: /(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    replacement: '[PHONE_SCRUBBED]',
    category: 'phone'
  },
  {
    name: 'International Phone Number',
    pattern: /\+[1-9]\d{1,14}\b/g,
    replacement: '[INTL_PHONE_SCRUBBED]',
    category: 'phone'
  },

  // IP Addresses
  {
    name: 'IPv4 Address',
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    replacement: '[IPv4_SCRUBBED]',
    category: 'ip_address'
  },
  {
    name: 'IPv6 Address',
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b/g,
    replacement: '[IPv6_SCRUBBED]',
    category: 'ip_address'
  },

  // Physical Addresses (US-style)
  {
    name: 'US Street Address',
    pattern: /\b\d{1,6}\s+(?:[A-Z][a-z]+\s*){1,4}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Pl(?:ace)?|Way|Cir(?:cle)?|Pkwy|Parkway|Ter(?:race)?|Hwy|Highway)\.?\s*(?:#\s*\d+|(?:Apt|Suite|Ste|Unit|Fl|Floor)\s*#?\s*\d+[A-Za-z]?)?\b/gi,
    replacement: '[ADDRESS_SCRUBBED]',
    category: 'address'
  },

  // Date of Birth
  {
    name: 'Date of Birth with label',
    pattern: /(?:d\.?o\.?b\.?|date\s*of\s*birth|birth\s*date|birthday)\s*[=:]\s*['"]?\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}['"]?/gi,
    replacement: '[DOB_SCRUBBED]',
    category: 'dob'
  },

  // Passport Numbers
  {
    name: 'US Passport Number',
    pattern: /(?:passport(?:\s*(?:number|num|no|#))?)\s*[=:]\s*['"]?[A-Z]?\d{8,9}['"]?/gi,
    replacement: '[PASSPORT_SCRUBBED]',
    category: 'government_id'
  },

  // Driver's License (generic US pattern)
  {
    name: 'Drivers License with label',
    pattern: /(?:driver'?s?\s*(?:license|licence|lic)(?:\s*(?:number|num|no|#))?|dl\s*(?:number|num|no|#)?)\s*[=:]\s*['"]?[A-Z0-9\-]{5,15}['"]?/gi,
    replacement: '[DRIVERS_LICENSE_SCRUBBED]',
    category: 'government_id'
  },

  // Name patterns (when labeled)
  {
    name: 'Full Name with label',
    pattern: /(?:(?:full\s*)?name|first\s*name|last\s*name|surname|given\s*name|family\s*name)\s*[=:]\s*['"]([^'"]{2,50})['"]/gi,
    replacement: '$1=[NAME_SCRUBBED]',
    category: 'name'
  }
];

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Performs the Luhn algorithm check on a credit card number string.
 * @param {string} cardNumber - The credit card number (may contain spaces or hyphens)
 * @returns {boolean} Whether the card number passes the Luhn check
 */
function luhnCheck(cardNumber) {
  const digits = cardNumber.replace(/[\s-]/g, '');
  if (!/^\d+$/.test(digits)) return false;
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let isEven = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

/**
 * Applies a set of scrub patterns to text and collects findings.
 * @param {string} text - The text to scrub
 * @param {ScrubPattern[]} patterns - Array of patterns to apply
 * @param {Array} [findings] - Optional array to collect findings
 * @returns {string} The scrubbed text
 */
function applyPatterns(text, patterns, findings) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }

  let result = text;

  for (const patternDef of patterns) {
    // Skip context-required patterns when used in generic scrubbing
    if (patternDef.contextRequired) continue;

    // Reset regex lastIndex for global patterns
    patternDef.pattern.lastIndex = 0;

    if (findings) {
      // Collect findings before replacing
      let match;
      const regex = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
      while ((match = regex.exec(text)) !== null) {
        // If there's a validator, check it
        if (patternDef.validator && !patternDef.validator(match[0])) {
          continue;
        }

        findings.push({
          type: patternDef.name,
          category: patternDef.category,
          match: match[0],
          index: match.index,
          length: match[0].length
        });
      }
    }

    // Apply replacement with optional validation
    if (patternDef.validator) {
      result = result.replace(patternDef.pattern, (match, ...args) => {
        if (patternDef.validator(match)) {
          return patternDef.replacement.replace(/\$(\d+)/g, (_, n) => args[parseInt(n) - 1] || '');
        }
        return match;
      });
    } else {
      patternDef.pattern.lastIndex = 0;
      result = result.replace(patternDef.pattern, patternDef.replacement);
    }
  }

  return result;
}

/**
 * Masks a matched string, showing only the first and last few characters.
 * @param {string} str - The string to mask
 * @param {number} [showChars=2] - Number of characters to show at start and end
 * @returns {string} The masked string
 */
function maskString(str, showChars = 2) {
  if (str.length <= showChars * 2) {
    return '*'.repeat(str.length);
  }
  const start = str.substring(0, showChars);
  const end = str.substring(str.length - showChars);
  const middle = '*'.repeat(Math.min(str.length - showChars * 2, 20));
  return `${start}${middle}${end}`;
}

// ============================================================================
// Main Exported Functions
// ============================================================================

/**
 * Scrubs environment variable values from the given text.
 * Detects and replaces values assigned to environment variables that appear
 * to contain sensitive information such as keys, secrets, tokens, and passwords.
 *
 * @param {string} text - The text to scrub
 * @returns {string} The text with environment variable values scrubbed
 * @throws {TypeError} If text is not a string
 *
 * @example
 * const scrubbed = scrubEnvironmentVariables('export AWS_SECRET_KEY="myS3cretK3y123"');
 * // Returns: 'AWS_SECRET_KEY=[ENV_VAR_SCRUBBED]'
 *
 * @example
 * const scrubbed = scrubEnvironmentVariables('DATABASE_PASSWORD=super_secret_pass');
 * // Returns: 'DATABASE_PASSWORD=[ENV_VAR_SCRUBBED]'
 */
function scrubEnvironmentVariables(text) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }
  return applyPatterns(text, ENV_VAR_PATTERNS);
}

/**
 * Scrubs cloud provider credentials, API keys, database connection strings,
 * and other service tokens from the given text.
 *
 * Supports detection of:
 * - AWS: Access Key IDs (AKIA...), Secret Access Keys, Session Tokens, ARNs, MWS Keys
 * - GCP: API Keys (AIza...), Service Account emails, OAuth tokens (ya29...), Private Keys
 * - GitHub: Personal Access Tokens (ghp_), Fine-grained tokens, OAuth, U2S, S2S, Refresh tokens
 * - Database: MongoDB, PostgreSQL, MySQL, Redis, MSSQL, JDBC connection strings
 * - Other: Slack, Stripe, Twilio, SendGrid, NPM tokens, SSH keys, certificates
 * - Generic: Bearer tokens, Basic auth, API key headers, password assignments
 *
 * @param {string} text - The text to scrub
 * @returns {string} The text with credentials scrubbed
 * @throws {TypeError} If text is not a string
 *
 * @example
 * const scrubbed = scrubCredentials('key: AKIAIOSFODNN7EXAMPLE');
 * // Returns: 'key: [AWS_ACCESS_KEY_SCRUBBED]'
 *
 * @example
 * const scrubbed = scrubCredentials('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12');
 * // Returns: 'token: [GITHUB_PAT_SCRUBBED]'
 *
 * @example
 * const scrubbed = scrubCredentials('mongodb://admin:password123@cluster0.mongodb.net/mydb');
 * // Returns: 'mongodb://[DB_CREDENTIALS_SCRUBBED]@[DB_HOST_SCRUBBED]'
 */
function scrubCredentials(text) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }
  return applyPatterns(text, CREDENTIAL_PATTERNS);
}

/**
 * Scrubs Personally Identifiable Information (PII) from the given text.
 *
 * Detects and replaces:
 * - Social Security Numbers (SSN): Both formatted (XXX-XX-XXXX) and unformatted, with validation
 * - Credit Card Numbers: Visa, Mastercard, Amex, Discover, Diners Club, JCB with Luhn validation
 * - CVV/CVC codes when labeled
 * - Email addresses
 * - Phone numbers (US and international)
 * - IP addresses (IPv4 and IPv6)
 * - Physical addresses (US-style street addresses)
 * - Dates of birth when labeled
 * - Passport numbers when labeled
 * - Driver's license numbers when labeled
 * - Names when labeled (e.g., "name: John Doe")
 *
 * @param {string} text - The text to scrub
 * @returns {string} The text with PII scrubbed
 * @throws {TypeError} If text is not a string
 *
 * @example
 * const scrubbed = scrubPII('SSN: 123-45-6789');
 * // Returns: 'SSN: [SSN_SCRUBBED]'
 *
 * @example
 * const scrubbed = scrubPII('Card: 4111-1111-1111-1111');
 * // Returns: 'Card: [VISA_CARD_SCRUBBED]'
 *
 * @example
 * const scrubbed = scrubPII('Contact: user@example.com');
 * // Returns: 'Contact: [EMAIL_SCRUBBED]'
 */
function scrubPII(text) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }
  return applyPatterns(text, PII_PATTERNS);
}

/**
 * Scrubs all known sensitive data types from text (environment variables,
 * credentials, and PII combined).
 *
 * @param {string} text - The text to scrub
 * @returns {string} The fully scrubbed text
 * @throws {TypeError} If text is not a string
 *
 * @example
 * const scrubbed = scrubAll('export AWS_KEY="AKIAIOSFODNN7EXAMPLE" email: user@test.com SSN: 123-45-6789');
 */
function scrubAll(text) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }
  let result = text;
  result = scrubCredentials(result);
  result = scrubEnvironmentVariables(result);
  result = scrubPII(result);
  return result;
}

/**
 * Creates an HTTP/HTTPS proxy server that automatically scrubs sensitive data
 * from request bodies before forwarding them to the target LLM API URL.
 *
 * The proxy:
 * - Intercepts incoming HTTP requests
 * - Scrubs request bodies for environment variables, credentials, and PII
 * - Forwards scrubbed requests to the target URL
 * - Returns the response from the target API
 * - Adds X-Scrubbed header to indicate processing
 * - Logs scrub reports for each request (when verbose)
 *
 * @param {string} targetUrl - The target LLM API URL to proxy requests to
 * @param {Object} [options] - Configuration options
 * @param {number} [options.port=3000] - Port for the proxy server to listen on
 * @param {string} [options.host='localhost'] - Host for the proxy server
 * @param {boolean} [options.verbose=false] - Whether to log scrub reports
 * @param {boolean} [options.scrubResponse=false] - Whether to also scrub response bodies
 * @param {string[]} [options.scrubTypes=['all']] - Types of scrubbing: 'env', 'credentials', 'pii', 'all'
 * @param {Function} [options.onScrub] - Callback called with scrub report for each request
 * @returns {http.Server} The proxy HTTP server instance
 * @throws {TypeError} If targetUrl is not a valid URL string
 *
 * @example
 * const proxy = createScrubberProxy('https://api.openai.com/v1/chat/completions', {
 *   port: 8080,
 *   verbose: true,
 *   onScrub: (report) => console.log('Scrubbed:', report.summary.totalFindings, 'items')
 * });
 *
 * // Now send requests to http://localhost:8080 instead of the OpenAI API
 * // All sensitive data in request bodies will be automatically scrubbed
 *
 * @example
 * // Cleanup
 * proxy.close();
 */
function createScrubberProxy(targetUrl, options = {}) {
  if (typeof targetUrl !== 'string') {
    throw new TypeError('targetUrl must be a string');
  }

  const parsedTarget = new URL(targetUrl);

  const {
    port = 3000,
    host = 'localhost',
    verbose = false,
    scrubResponse = false,
    scrubTypes = ['all'],
    onScrub = null
  } = options;

  /**
   * Applies the configured scrub types to text
   * @param {string} text - Text to scrub
   * @returns {string} Scrubbed text
   */
  function applyScrubbing(text) {
    if (scrubTypes.includes('all')) {
      return scrubAll(text);
    }
    let result = text;
    if (scrubTypes.includes('env')) {
      result = scrubEnvironmentVariables(result);
    }
    if (scrubTypes.includes('credentials')) {
      result = scrubCredentials(result);
    }
    if (scrubTypes.includes('pii')) {
      result = scrubPII(result);
    }
    return result;
  }

  const server = http.createServer((req, res) => {
    let body = [];

    req.on('data', (chunk) => {
      body.push(chunk);
    });

    req.on('end', () => {
      const rawBody = Buffer.concat(body).toString('utf-8');

      // Generate report before scrubbing if needed
      let report = null;
      if (verbose || onScrub) {
        report = generateScrubReport(rawBody);
      }

      // Scrub the body
      const scrubbedBody = applyScrubbing(rawBody);

      if (verbose) {
        console.log(`[LLM-Scrubber] Request to ${req.method} ${req.url}`);
        console.log(`[LLM-Scrubber] Findings: ${report.summary.totalFindings}`);
        if (report.findings.length > 0) {
          console.log(`[LLM-Scrubber] Categories: ${Object.keys(report.summary.byCategory).join(', ')}`);
        }
      }

      if (onScrub && report) {
        try {
          onScrub(report);
        } catch (e) {
          console.error('[LLM-Scrubber] onScrub callback error:', e.message);
        }
      }

      // Forward the scrubbed request
      const targetProtocol = parsedTarget.protocol === 'https:' ? https : http;
      const forwardPath = parsedTarget.pathname + (req.url === '/' ? '' : req.url);

      const forwardHeaders = { ...req.headers };
      delete forwardHeaders['host'];
      forwardHeaders['host'] = parsedTarget.host;
      forwardHeaders['content-length'] = Buffer.byteLength(scrubbedBody);

      const proxyReq = targetProtocol.request(
        {
          hostname: parsedTarget.hostname,
          port: parsedTarget.port || (parsedTarget.protocol === 'https:' ? 443 : 80),
          path: forwardPath,
          method: req.method,
          headers: forwardHeaders
        },
        (proxyRes) => {
          let responseBody = [];

          proxyRes.on('data', (chunk) => {
            responseBody.push(chunk);
          });

          proxyRes.on('end', () => {
            let responseData = Buffer.concat(responseBody);

            if (scrubResponse) {
              const responseText = responseData.toString('utf-8');
              const scrubbedResponse = applyScrubbing(responseText);
              responseData = Buffer.from(scrubbedResponse, 'utf-8');
            }

            const responseHeaders = { ...proxyRes.headers };
            responseHeaders['x-scrubbed'] = 'true';
            responseHeaders['x-scrubbed-findings'] = report
              ? String(report.summary.totalFindings)
              : '0';
            responseHeaders['content-length'] = responseData.length;

            res.writeHead(proxyRes.statusCode, responseHeaders);
            res.end(responseData);
          });
        }
      );

      proxyReq.on('error', (err) => {
        console.error('[LLM-Scrubber] Proxy error:', err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            error: 'Bad Gateway',
            message: 'Failed to connect to target API',
            details: err.message
          })
        );
      });

      proxyReq.write(scrubbedBody);
      proxyReq.end();
    });

    req.on('error', (err) => {
      console.error('[LLM-Scrubber] Request error:', err.message);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad Request', message: err.message }));
    });
  });

  server.listen(port, host, () => {
    if (verbose) {
      console.log(`[LLM-Scrubber] Proxy server listening on http://${host}:${port}`);
      console.log(`[LLM-Scrubber] Forwarding to ${targetUrl}`);
      console.log(`[LLM-Scrubber] Scrub types: ${scrubTypes.join(', ')}`);
    }
  });

  return server;
}

/**
 * @typedef {Object} ScrubFinding
 * @property {string} type - The name of the pattern that matched
 * @property {string} category - The category of sensitive data found
 * @property {string} match - The matched text (masked for security)
 * @property {number} index - The character index where the match was found
 * @property {number} length - The length of the matched text
 */

/**
 * @typedef {Object} ScrubReportSummary
 * @property {number} totalFindings - Total number of sensitive data items found
 * @property {Object.<string, number>} byCategory - Count of findings by category
 * @property {Object.<string, number>} byType - Count of findings by specific type
 * @property {number} originalLength - Length of the original text
 * @property {number} scrubbedLength - Length of the scrubbed text
 * @property {string} riskLevel - Risk assessment: 'none', 'low', 'medium', 'high', 'critical'
 */

/**
 * @typedef {Object} ScrubReport
 * @property {string} timestamp - ISO 8601 timestamp of the report generation
 * @property {ScrubReportSummary} summary - Summary statistics
 * @property {ScrubFinding[]} findings - Detailed list of all findings
 * @property {string} scrubbedText - The fully scrubbed version of the input text
 * @property {string[]} recommendations - Security recommendations based on findings
 */

/**
 * Generates a comprehensive report of all sensitive data found in the given text.
 * The report includes detailed findings, summary statistics, risk assessment,
 * and the scrubbed version of the text.
 *
 * The report scans for all categories:
 * - Environment variables with sensitive values
 * - Cloud provider credentials (AWS, GCP, GitHub, etc.)
 * - Database connection strings with embedded credentials
 * - PII (SSN, credit cards, emails, phone numbers, addresses, etc.)
 *
 * Matched text in findings is automatically masked for safe logging/storage.
 *
 * @param {string} text - The text to analyze and report on
 * @returns {ScrubReport} A comprehensive scrub report
 * @throws {TypeError} If text is not a string
 *
 * @example
 * const report = generateScrubReport('My AWS key is AKIAIOSFODNN7EXAMPLE and email is user@test.com');
 * console.log(report.summary.totalFindings); // 2
 * console.log(report.summary.riskLevel); // 'high'
 * console.log(report.summary.byCategory);
 * // { aws_credential: 1, email: 1 }
 *
 * @example
 * const report = generateScrubReport('No sensitive data here.');
 * console.log(report.summary.totalFindings); // 0
 * console.log(report.summary.riskLevel); // 'none'
 */
function generateScrubReport(text) {
  if (typeof text !== 'string') {
    throw new TypeError('Input must be a string');
  }

  /** @type {ScrubFinding[]} */
  const findings = [];

  // Collect findings from all pattern categories
  applyPatterns(text, ENV_VAR_PATTERNS, findings);
  applyPatterns(text, CREDENTIAL_PATTERNS, findings);
  applyPatterns(text, PII_PATTERNS, findings);

  // Deduplicate findings based on index and length
  const seen = new Set();
  const uniqueFindings = findings.filter((finding) => {
    const key = `${finding.index}:${finding.length}:${finding.type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by index
  uniqueFindings.sort((a, b) => a.index - b.index);

  // Mask the matched text for safe reporting
  const maskedFindings = uniqueFindings.map((finding) => ({
    ...finding,
    match: maskString(finding.match, 3)
  }));

  // Generate summary statistics
  const byCategory = {};
  const byType = {};

  for (const finding of uniqueFindings) {
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
    byType[finding.type] = (byType[finding.type] || 0) + 1;
  }

  // Generate scrubbed text
  const scrubbedText = scrubAll(text);

  // Assess risk level
  const totalFindings = uniqueFindings.length;
  let riskLevel = 'none';

  if (totalFindings > 0) {
    const hasCritical = uniqueFindings.some((f) =>
      [
        'aws_credential',
        'gcp_credential',
        'github_credential',
        'database_credential',
        'ssh_credential',
        'ssn'
      ].includes(f.category)
    );
    const hasHigh = uniqueFindings.some((f) =>
      ['credit_card', 'api_credential', 'generic_credential', 'government_id'].includes(f.category)
    );
    const hasMedium = uniqueFindings.some((f) =>
      ['environment_variable', 'service_credential', 'email', 'phone'].includes(f.category)
    );

    if (hasCritical || totalFindings >= 10) {
      riskLevel = 'critical';
    } else if (hasHigh || totalFindings >= 5) {
      riskLevel = 'high';
    } else if (hasMedium || totalFindings >= 2) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }
  }

  // Generate recommendations
  const recommendations = [];

  if (byCategory.aws_credential) {
    recommendations.push(
      'AWS credentials detected. Rotate keys immediately and use IAM roles or AWS Secrets Manager instead of hardcoding.'
    );
  }
  if (byCategory.gcp_credential) {
    recommendations.push(
      'GCP credentials detected. Use workload identity federation or Secret Manager. Avoid embedding service account keys.'
    );
  }
  if (byCategory.github_credential) {
    recommendations.push(
      'GitHub tokens detected. Revoke and regenerate tokens. Use fine-grained tokens with minimal permissions.'
    );
  }
  if (byCategory.database_credential) {
    recommendations.push(
      'Database credentials detected. Use connection pooling with secret management. Never include credentials in code.'
    );
  }
  if (byCategory.ssn) {
    recommendations.push(
      'SSN detected. This is highly sensitive PII. Ensure compliance with regulations (e.g., HIPAA, state privacy laws).'
    );
  }
  if (byCategory.credit_card) {
    recommendations.push(
      'Credit card numbers detected. Ensure PCI-DSS compliance. Use tokenization services instead of raw card numbers.'
    );
  }
  if (byCategory.email) {
    recommendations.push(
      'Email addresses detected. Consider if these need to be sent to external APIs for GDPR/CCPA compliance.'
    );
  }
  if (byCategory.environment_variable) {
    recommendations.push(
      'Environment variable assignments with sensitive values detected. Use a secrets manager and avoid logging env vars.'
    );
  }
  if (byCategory.ssh_credential || byCategory.certificate) {
    recommendations.push(
      'SSH keys or certificates detected. Never transmit private keys. Use certificate management tools.'
    );
  }
  if (byCategory.ip_address) {
    recommendations.push(
      'IP addresses detected. Consider if exposing infrastructure details to external APIs is acceptable.'
    );
  }
  if (byCategory.url_credential) {
    recommendations.push(
      'URLs with embedded credentials detected. Extract credentials and use secure configuration management.'
    );
  }
  if (byCategory.service_credential) {
    recommendations.push(
      'Third-party service tokens detected. Rotate tokens and store them in a secrets manager.'
    );
  }

  if (totalFindings === 0) {
    recommendations.push('No sensitive data detected. Text appears safe for external API transmission.');
  }

  return {
    timestamp: new Date().toISOString(),
    summary: {
      totalFindings,
      byCategory,
      byType,
      originalLength: text.length,
      scrubbedLength: scrubbedText.length,
      riskLevel
    },
    findings: maskedFindings,
    scrubbedText,
    recommendations
  };
}

// ============================================================================
// Module Exports
// ============================================================================

module.exports = {
  scrubEnvironmentVariables,
  scrubCredentials,
  scrubPII,
  scrubAll,
  createScrubberProxy,
  generateScrubReport,
  // Expose helpers for advanced usage
  _internals: {
    luhnCheck,
    maskString,
    applyPatterns,
    ENV_VAR_PATTERNS,
    CREDENTIAL_PATTERNS,
    PII_PATTERNS
  }
};