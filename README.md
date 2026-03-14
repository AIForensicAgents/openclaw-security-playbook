<!-- 
  Open Graph Meta Tags for Social Sharing
  <meta property="og:title" content="OpenClaw Security Playbook — Layer-by-Layer AI Agent Hardening" />
  <meta property="og:description" content="A comprehensive, five-layer security hardening framework for OpenClaw AI agent deployments. Covers input sanitization, gateway hardening, prompt firewalls, execution sandboxing, and audit log protection." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://github.com/AIForensicAgents/openclaw-security-playbook" />
  <meta property="og:image" content="https://repository-images.githubusercontent.com/placeholder/openclaw-security-playbook" />
  <meta property="twitter:card" content="summary_large_image" />
  <meta property="twitter:title" content="OpenClaw Security Playbook" />
  <meta property="twitter:description" content="Five-layer security hardening for OpenClaw AI agent deployments." />
-->

<h1>OpenClaw Security Playbook</h1>

<p>
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version 1.0.0" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License" />
  <img src="https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen?style=flat-square" alt="Node >= 18.0.0" />
  <img src="https://img.shields.io/badge/security-hardened-critical?style=flat-square" alt="Security Hardened" />
  <img src="https://img.shields.io/badge/tests-jest-purple?style=flat-square" alt="Tests: Jest" />
  <img src="https://img.shields.io/badge/docker-secure--build-blue?style=flat-square" alt="Docker Secure Build" />
  <img src="https://img.shields.io/badge/AI%20agent-defense--in--depth-orange?style=flat-square" alt="AI Agent Defense in Depth" />
</p>

<h2>Overview</h2>

<p>
  <strong>openclaw-security-playbook</strong> is a comprehensive, layer-by-layer security hardening framework designed specifically for <a href="https://github.com/AIForensicAgents">OpenClaw AI agent</a> deployments. It implements a <em>defense-in-depth</em> architecture organized into five discrete security layers — from raw input perception through orchestration, inference, execution, and feedback — ensuring that every stage of an AI agent's operational pipeline is protected against adversarial attacks, data leakage, prompt injection, and runtime exploitation.
</p>

<p>
  Built as a Node.js module with Express middleware support, the playbook provides production-ready security modules, Docker hardening configurations, and a unified audit CLI. Each layer can be adopted independently or composed together for full-stack agent security.
</p>

<h2>Architecture</h2>

<p>The framework is organized around five security layers that mirror the operational pipeline of an AI agent:</p>

<ol>
  <li><strong>Layer 1 — Perception (Input Sanitization):</strong> Sanitizes and validates all incoming multimodal inputs before they reach the agent.</li>
  <li><strong>Layer 2 — Orchestration (Gateway &amp; Memory Protection):</strong> Hardens the network gateway and protects the agent's memory/context store from poisoning.</li>
  <li><strong>Layer 3 — Inference (Prompt Firewall &amp; Context Scrubbing):</strong> Detects and blocks prompt injection attacks; scrubs sensitive data before it reaches LLM APIs.</li>
  <li><strong>Layer 4 — Execution (Sandbox &amp; Skill Validation):</strong> Enforces container-level hardening and validates skill/plugin integrity via hash-based whitelisting.</li>
  <li><strong>Layer 5 — Feedback (Audit Log Protection):</strong> Provides tamper-evident, append-only audit logging with HMAC chain integrity, alerting, and log forwarding.</li>
</ol>

<h2>Component Summary</h2>

<table>
  <thead>
    <tr>
      <th>Component</th>
      <th>Purpose</th>
      <th>Complexity</th>
      <th>Key Files</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Entry Point &amp; Unified API</strong></td>
      <td>Loads all five security layers, exposes a unified API, and provides CLI audit support</td>
      <td>Medium</td>
      <td><code>src/index.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 1 — Input Sanitizer</strong></td>
      <td>Multimodal input sanitization: image metadata stripping, text sanitization, HTML stripping, prompt injection pattern detection, encoding validation</td>
      <td>High</td>
      <td><code>src/layer1-perception/sanitizer.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 2 — Gateway Hardener</strong></td>
      <td>Loopback binding enforcement, mTLS configuration, rate limiting, firewall rule generation, Docker Compose security generation</td>
      <td>Expert</td>
      <td><code>src/layer2-orchestration/gateway-hardener.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 2 — Memory Guardian</strong></td>
      <td>Scans agent memory/context files for suspicious patterns, quarantines poisoned entries, generates memory health reports</td>
      <td>High</td>
      <td><code>src/layer2-orchestration/memory-guardian.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 3 — Prompt Firewall</strong></td>
      <td>Detects prompt injection attacks (system overrides, role hijacking, base64-encoded payloads, social engineering), assigns confidence scores, supports human-in-the-loop approval</td>
      <td>Expert</td>
      <td><code>src/layer3-inference/prompt-firewall.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 3 — Context Scrubber</strong></td>
      <td>Scrubs environment variables, API keys, AWS/GCP/Azure credentials, SSH keys, database connection strings, PII (SSN, credit cards) from text before sending to LLM APIs; includes proxy and reporting</td>
      <td>Expert</td>
      <td><code>src/layer3-inference/context-scrubber.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 4 — Sandbox Hardener</strong></td>
      <td>Audits Docker Compose files for security misconfigurations, generates hardened Dockerfiles, enforces read-only rootfs, capability dropping, resource limits</td>
      <td>Expert</td>
      <td><code>src/layer4-execution/sandbox-hardener.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 4 — Skill Validator</strong></td>
      <td>Validates OpenClaw skill/plugin integrity via SHA-256 hash whitelisting, scans for infostealer patterns, generates security reports</td>
      <td>High</td>
      <td><code>src/layer4-execution/skill-validator.js</code></td>
    </tr>
    <tr>
      <td><strong>Layer 5 — Audit Fortress</strong></td>
      <td>Append-only audit log with HMAC-chained entries, tamper detection, alert rules (bash tool execution, unknown IPs, file deletion), log forwarding to S3/webhooks</td>
      <td>Expert</td>
      <td><code>src/layer5-feedback/audit-fortress.js</code></td>
    </tr>
    <tr>
      <td><strong>Security Configuration</strong></td>
      <td>Default security policies: TLS settings, rate limits, sanitization rules, prompt injection patterns, sandbox policies, audit configuration</td>
      <td>Medium</td>
      <td><code>config/default-security.json</code></td>
    </tr>
    <tr>
      <td><strong>Skill Whitelist</strong></td>
      <td>Approved skill plugin registry with SHA-256 hashes, approval metadata, and auto-reject policy for unknown skills</td>
      <td>Low</td>
      <td><code>config/skill-whitelist.json</code></td>
    </tr>
    <tr>
      <td><strong>Docker Hardened Image</strong></td>
      <td>Multi-stage secure Dockerfile: Alpine-based, non-root user, read-only rootfs, dumb-init, strict file permissions, health checks</td>
      <td>High</td>
      <td><code>docker/Dockerfile.secure</code></td>
    </tr>
    <tr>
      <td><strong>Docker Compose (Secure)</strong></td>
      <td>Production-ready Compose file with read-only root, dropped capabilities, no-new-privileges, resource limits, tmpfs, health checks, network isolation</td>
      <td>Medium</td>
      <td><code>docker/docker-compose.secure.yml</code></td>
    </tr>
    <tr>
      <td><strong>Test Suite</strong></td>
      <td>Jest-based tests covering Layer 1 (input sanitization, image metadata stripping, prompt injection detection) and Layer 3 (prompt firewall, context scrubbing, PII detection)</td>
      <td>Medium</td>
      <td><code>tests/layer1.test.js</code>, <code>tests/layer3.test.js</code></td>
    </tr>
    <tr>
      <td><strong>Security Policy &amp; Contributing</strong></td>
      <td>Responsible disclosure policy with PGP key, contribution guidelines</td>
      <td>Low</td>
      <td><code>.github/SECURITY.md</code>, <code>CONTRIBUTING.md</code></td>
    </tr>
  </tbody>
</table>

<h2>Detailed Layer Documentation</h2>

<!-- ====================================================================== -->
<h3>Layer 1 — Perception: Input Sanitization</h3>
<!-- ====================================================================== -->

<p><strong>Directory:</strong> <code>src/layer1-perception/</code></p>
<p><strong>Complexity:</strong> High</p>

<p>
  This layer acts as the first line of defense, intercepting and sanitizing all incoming data before it reaches any downstream processing. It handles multimodal inputs including text, images, audio references, and documents.
</p>

<h4>Key Capabilities</h4>
<ul>
  <li><strong>Image Metadata Stripping:</strong> Removes EXIF, GPS, IPTC, XMP, and MakerNote metadata from image buffers to prevent location tracking and data leakage.</li>
  <li><strong>Text Sanitization:</strong> Strips control characters, normalizes Unicode (NFC), validates UTF-8 encoding, and enforces maximum input length (configurable, default 64KB).</li>
  <li><strong>HTML Sanitization:</strong> Strips all HTML tags to prevent XSS and markup injection.</li>
  <li><strong>SQL Injection Prevention:</strong> Detects and blocks SQL injection patterns in input text.</li>
  <li><strong>Path Traversal Prevention:</strong> Blocks directory traversal sequences in file paths.</li>
  <li><strong>Prompt Injection Detection:</strong> Pattern-based detection of common prompt injection phrases (e.g., <em>"ignore previous instructions"</em>, <em>"you are now"</em>) with configurable similarity threshold and block/log modes.</li>
  <li><strong>Express Middleware:</strong> Can be mounted as Express middleware to create a sanitization gateway for HTTP APIs.</li>
  <li><strong>Structured Logging:</strong> Internal logger with levels (DEBUG through CRITICAL) and request ID correlation.</li>
</ul>

<h4>Key Files</h4>
<ul>
  <li><code>src/layer1-perception/sanitizer.js</code> — Core multimodal sanitization module with logging, image processing, and middleware support.</li>
</ul>

<h4>Configuration</h4>
<p>Sanitization behavior is governed by the <code>sanitization</code> section in <code>config/default-security.json</code>, including input length limits, encoding rules, injection detection patterns, and HTML/SQL/path traversal settings.</p>

<!-- ====================================================================== -->
<h3>Layer 2 — Orchestration: Gateway &amp; Memory Protection</h3>
<!-- ====================================================================== -->

<p><strong>Directory:</strong> <code>src/layer2-orchestration/</code></p>
<p><strong>Complexity:</strong> Expert</p>

<p>
  This layer secures the agent's communication gateway and its persistent memory store. It ensures that the agent's API surface is minimized and that its context/memory cannot be poisoned by adversarial entries.
</p>

<h4>Gateway Hardener</h4>
<ul>
  <li><strong>Loopback Binding:</strong> Enforces binding to <code>127.0.0.1</code> only (with optional IPv6 loopback), preventing external network exposure of the OpenClaw gateway on port 18789.</li>
  <li><strong>Mutual TLS (mTLS):</strong> Generates and enforces mTLS configuration with client certificate requirements, TLS 1.3 minimum, and strong cipher suites (<code>TLS_AES_256_GCM_SHA384</code>, <code>TLS_CHACHA20_POLY1305_SHA256</code>).</li>
  <li><strong>Firewall Rule Generation:</strong> Programmatically generates iptables rules to drop external traffic to the gateway port.</li>
  <li><strong>Rate Limiting:</strong> Configurable per-IP rate limiting (default 120 req/min with burst of 20).</li>
  <li><strong>Docker Compose Generation:</strong> Generates hardened <code>docker-compose.yml</code> snippets with security options (read-only rootfs, no-new-privileges, capability dropping, resource limits).</li>
  <li><strong>Connection Limits:</strong> Enforces maximum concurrent connections and per-second rate limits.</li>
</ul>

<h4>Memory Guardian</h4>
<ul>
  <li><strong>Memory File Scanning:</strong> Scans agent memory/context files (line-by-line) for suspicious patterns such as injected instructions, encoded payloads, or anomalous entries.</li>
  <li><strong>Severity Classification:</strong> Classifies findings as low, medium, high, or critical severity.</li>
  <li><strong>Quarantine:</strong> Isolates suspicious entries into a quarantine file while preserving clean lines in the original, maintaining operational continuity.</li>
  <li><strong>Health Reports:</strong> Generates detailed memory health reports including file metadata (size, permissions, modification time), scan results, and quarantine statistics.</li>
</ul>

<h4>Key Files</h4>
<ul>
  <li><code>src/layer2-orchestration/gateway-hardener.js</code> — Gateway security hardening with mTLS, loopback enforcement, rate limiting, and Docker Compose generation.</li>
  <li><code>src/layer2-orchestration/memory-guardian.js</code> — Memory/context file scanning, quarantine, and reporting.</li>
</ul>

<!-- ====================================================================== -->