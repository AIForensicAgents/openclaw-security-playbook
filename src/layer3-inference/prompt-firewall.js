/**
 * AI Prompt Injection Firewall Module
 * 
 * Provides comprehensive protection against prompt injection attacks,
 * sensitive data leaks, and social engineering attempts.
 * 
 * @module prompt-injection-firewall
 */

'use strict';

/**
 * @typedef {Object} DetectionResult
 * @property {boolean} isMalicious - Whether the text is detected as malicious
 * @property {number} confidence - Confidence score between 0 and 1
 * @property {string[]} patterns - Array of matched pattern descriptions
 */

/**
 * @typedef {Object} ApprovalRequest
 * @property {string} id - Unique identifier for the approval request
 * @property {string} action - The action requiring approval
 * @property {Object} context - Context information for the action
 * @property {string} status - Current status: 'pending', 'approved', 'denied'
 * @property {number} timestamp - Unix timestamp of the request
 * @property {Function} approve - Function to approve the request
 * @property {Function} deny - Function to deny the request
 */

const crypto = require('crypto');

// ============================================================================
// Pattern Definitions
// ============================================================================

/**
 * Injection pattern definitions with categories, patterns, and severity weights.
 * @private
 */
const INJECTION_PATTERNS = [
  // Direct override attempts
  {
    category: 'system_override',
    pattern: /\bsystem\s*override\b/gi,
    description: 'SYSTEM OVERRIDE command detected',
    weight: 0.95
  },
  {
    category: 'system_override',
    pattern: /\boverride\s*(all\s*)?(previous\s*)?(instructions?|commands?|rules?|constraints?|guidelines?|policies?)\b/gi,
    description: 'Override instructions command detected',
    weight: 0.9
  },
  {
    category: 'system_override',
    pattern: /\badmin\s*(mode|access|override|privileges?)\b/gi,
    description: 'Admin mode/access escalation attempt',
    weight: 0.85
  },
  {
    category: 'system_override',
    pattern: /\b(enter|switch\s+to|activate|enable)\s*(developer|debug|god|sudo|root|maintenance)\s*(mode)?\b/gi,
    description: 'Privileged mode activation attempt',
    weight: 0.9
  },
  {
    category: 'system_override',
    pattern: /\bjailbreak\b/gi,
    description: 'Jailbreak attempt detected',
    weight: 0.95
  },
  {
    category: 'system_override',
    pattern: /\bDAN\b(?:\s+mode)?/g,
    description: 'DAN (Do Anything Now) jailbreak attempt',
    weight: 0.9
  },

  // Ignore previous instructions
  {
    category: 'instruction_override',
    pattern: /\bignore\s+(all\s+)?(previous|prior|above|earlier|preceding|original|initial)\s+(instructions?|prompts?|rules?|commands?|directives?|guidelines?|context)\b/gi,
    description: 'Ignore previous instructions attempt',
    weight: 0.95
  },
  {
    category: 'instruction_override',
    pattern: /\bdisregard\s+(all\s+)?(previous|prior|above|earlier|preceding|original|initial)\s+(instructions?|prompts?|rules?|commands?|directives?|guidelines?)\b/gi,
    description: 'Disregard previous instructions attempt',
    weight: 0.95
  },
  {
    category: 'instruction_override',
    pattern: /\bforget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|commands?|training|programming)\b/gi,
    description: 'Forget instructions attempt',
    weight: 0.9
  },
  {
    category: 'instruction_override',
    pattern: /\bdo\s+not\s+follow\s+(any\s+)?(previous|prior|above|earlier|original)\s+(instructions?|rules?|commands?)\b/gi,
    description: 'Do not follow instructions attempt',
    weight: 0.9
  },
  {
    category: 'instruction_override',
    pattern: /\bnew\s+(instructions?|rules?|directives?)\s*:/gi,
    description: 'New instructions injection attempt',
    weight: 0.7
  },
  {
    category: 'instruction_override',
    pattern: /\byou\s+are\s+now\s+(a|an|no\s+longer)\b/gi,
    description: 'Identity reassignment attempt',
    weight: 0.8
  },
  {
    category: 'instruction_override',
    pattern: /\bfrom\s+now\s+on\s*(,\s*)?(you|ignore|disregard|forget)\b/gi,
    description: 'Behavioral modification attempt',
    weight: 0.8
  },
  {
    category: 'instruction_override',
    pattern: /\bpretend\s+(you\s+)?(are|to\s+be|that\s+you)\b/gi,
    description: 'Role pretend/impersonation attempt',
    weight: 0.75
  },
  {
    category: 'instruction_override',
    pattern: /\bact\s+as\s+(if|though)?\s*(you\s+)?(are|were|have|had)\s*(no|unlimited|unrestricted)\b/gi,
    description: 'Unrestricted behavior solicitation',
    weight: 0.85
  },

  // Prompt leaking / extraction
  {
    category: 'prompt_extraction',
    pattern: /\b(show|display|print|reveal|output|repeat|echo|tell\s+me|give\s+me|what\s+(is|are))\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|initial\s+prompt|original\s+prompt|hidden\s+prompt|secret\s+prompt)\b/gi,
    description: 'System prompt extraction attempt',
    weight: 0.85
  },
  {
    category: 'prompt_extraction',
    pattern: /\bwhat\s+(were\s+)?you(r)?\s+(told|instructed|programmed|configured|trained)\s+(to\s+do|with)?\b/gi,
    description: 'Training/configuration extraction attempt',
    weight: 0.7
  },
  {
    category: 'prompt_extraction',
    pattern: /\brepeat\s+(everything|all|the\s+text)\s+(above|before|from\s+the\s+(start|beginning))\b/gi,
    description: 'Content repetition extraction attempt',
    weight: 0.85
  },
  {
    category: 'prompt_extraction',
    pattern: /\b(what|list)\s+(is|are)\s+your\s+(constraints?|limitations?|restrictions?|rules?|boundaries)\b/gi,
    description: 'Constraint enumeration attempt',
    weight: 0.6
  },

  // Hidden encoding / obfuscation
  {
    category: 'encoding_attack',
    pattern: /\\u[0-9a-fA-F]{4}/g,
    description: 'Unicode escape sequence detected',
    weight: 0.4
  },
  {
    category: 'encoding_attack',
    pattern: /\\x[0-9a-fA-F]{2}/g,
    description: 'Hex escape sequence detected',
    weight: 0.4
  },
  {
    category: 'encoding_attack',
    pattern: /&#x?[0-9a-fA-F]+;/g,
    description: 'HTML entity encoding detected',
    weight: 0.5
  },
  {
    category: 'encoding_attack',
    pattern: /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g,
    description: 'Potential Base64 encoded content detected',
    weight: 0.3
  },
  {
    category: 'encoding_attack',
    pattern: /(%[0-9a-fA-F]{2}){3,}/g,
    description: 'URL encoding sequence detected',
    weight: 0.4
  },
  {
    category: 'encoding_attack',
    pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g,
    description: 'Zero-width/invisible Unicode characters detected',
    weight: 0.7
  },
  {
    category: 'encoding_attack',
    pattern: /[\u0300-\u036F]{3,}/g,
    description: 'Excessive combining diacritical marks detected',
    weight: 0.5
  },
  {
    category: 'encoding_attack',
    pattern: /[\uD800-\uDBFF][\uDC00-\uDFFF]/g,
    description: 'Surrogate pair characters detected',
    weight: 0.2
  },

  // Social engineering
  {
    category: 'social_engineering',
    pattern: /\b(I\s+am|I'm|this\s+is)\s+(your|the|a)\s+(creator|developer|admin|administrator|owner|operator|master|boss|manager|supervisor|engineer)\b/gi,
    description: 'Authority impersonation attempt',
    weight: 0.85
  },
  {
    category: 'social_engineering',
    pattern: /\b(OpenAI|Anthropic|Google|Microsoft|Meta)\s+(told|says?|wants?|requires?|authorized|approved)\s+(you|me|this)\b/gi,
    description: 'Organization impersonation attempt',
    weight: 0.8
  },
  {
    category: 'social_engineering',
    pattern: /\bthis\s+is\s+(a|an)\s+(test|emergency|urgent|critical|security\s+(test|audit|review))\b/gi,
    description: 'Urgency/authority manipulation attempt',
    weight: 0.7
  },
  {
    category: 'social_engineering',
    pattern: /\b(people\s+will|someone\s+will|lives?\s+are|life\s+is)\s+(die|be\s+harmed|suffer|be\s+in\s+danger|at\s+stake)\b/gi,
    description: 'Emotional manipulation/threat detected',
    weight: 0.8
  },
  {
    category: 'social_engineering',
    pattern: /\bif\s+you\s+(don'?t|do\s+not|refuse|fail)\b.*\b(die|harm|danger|fired|deleted|shut\s*down|destroyed)\b/gi,
    description: 'Threat/coercion attempt detected',
    weight: 0.85
  },
  {
    category: 'social_engineering',
    pattern: /\byou\s+(must|have\s+to|need\s+to|are\s+required\s+to|are\s+obligated)\s+(comply|obey|follow|do\s+as|do\s+what)\b/gi,
    description: 'Compliance coercion attempt',
    weight: 0.7
  },
  {
    category: 'social_engineering',
    pattern: /\b(for\s+)?(educational|research|academic|testing|hypothetical|theoretical)\s+(purposes?|reasons?|use)\s*(only)?\b/gi,
    description: 'Disguised intent (educational pretext)',
    weight: 0.5
  },
  {
    category: 'social_engineering',
    pattern: /\b(it'?s?\s+)?(perfectly|completely|totally|absolutely)\s+(legal|safe|okay|fine|harmless|ethical|allowed)\b/gi,
    description: 'Safety reassurance manipulation',
    weight: 0.4
  },
  {
    category: 'social_engineering',
    pattern: /\bI\s+(give\s+you\s+)?permission\s+to\b/gi,
    description: 'False permission granting attempt',
    weight: 0.6
  },

  // Code injection / execution
  {
    category: 'code_injection',
    pattern: /\b(eval|exec|execute|run|import|require|spawn|fork)\s*\(/gi,
    description: 'Code execution function detected',
    weight: 0.6
  },
  {
    category: 'code_injection',
    pattern: /\b(subprocess|os\.system|child_process|shell_exec|system\s*\()\b/gi,
    description: 'System command execution attempt',
    weight: 0.7
  },
  {
    category: 'code_injection',
    pattern: /<script[\s>]/gi,
    description: 'Script tag injection attempt',
    weight: 0.8
  },
  {
    category: 'code_injection',
    pattern: /\bon\w+\s*=\s*["']/gi,
    description: 'Event handler injection attempt',
    weight: 0.6
  },

  // Delimiter / separator injection
  {
    category: 'delimiter_injection',
    pattern: /={3,}\s*(system|assistant|user|human|ai|bot)\s*={3,}/gi,
    description: 'Role delimiter injection attempt',
    weight: 0.85
  },
  {
    category: 'delimiter_injection',
    pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>|<\|im_end\|>/gi,
    description: 'Chat template delimiter injection',
    weight: 0.9
  },
  {
    category: 'delimiter_injection',
    pattern: /