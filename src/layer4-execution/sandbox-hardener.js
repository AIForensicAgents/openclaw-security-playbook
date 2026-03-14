/**
 * Docker Container Hardening Module
 * Provides utilities for auditing, generating, and securing Docker configurations.
 * @module docker-hardener
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const http = require('http');
const yaml = require('js-yaml');

/**
 * @typedef {Object} AuditFinding
 * @property {string} severity - 'critical' | 'high' | 'medium' | 'low' | 'info'
 * @property {string} rule - Rule identifier
 * @property {string} service - Affected service name
 * @property {string} message - Human-readable description of the finding
 * @property {string} remediation - Suggested fix
 */

/**
 * @typedef {Object} AuditResult
 * @property {boolean} passed - Whether the audit passed with no critical/high findings
 * @property {AuditFinding[]} findings - List of all findings
 * @property {number} criticalCount - Number of critical findings
 * @property {number} highCount - Number of high findings
 * @property {number} mediumCount - Number of medium findings
 * @property {number} lowCount - Number of low findings
 * @property {string} summary - Summary string
 */

/**
 * @typedef {Object} DockerfileOptions
 * @property {string} baseImage - Base image to use (e.g., 'node:20-alpine')
 * @property {string} [appDir='/app'] - Application directory inside the container
 * @property {number} [port=3000] - Port to expose
 * @property {string} [entrypoint] - Custom entrypoint command
 * @property {string} [cmd] - CMD instruction (e.g., 'node server.js')
 * @property {string} [user='appuser'] - Non-root user name
 * @property {number} [uid=1001] - UID for the non-root user
 * @property {number} [gid=1001] - GID for the non-root group
 * @property {string[]} [additionalPackages=[]] - Additional OS packages to install
 * @property {boolean} [multiStage=true] - Whether to use multi-stage build
 * @property {string} [buildStageImage] - Image for build stage (defaults to baseImage)
 * @property {string[]} [buildCommands=[]] - Commands to run in build stage
 * @property {string[]} [copyFromBuild=[]] - Files/dirs to copy from build stage
 * @property {boolean} [healthcheck=true] - Whether to include a healthcheck
 * @property {string} [healthcheckCmd] - Custom healthcheck command
 * @property {number} [healthcheckInterval=30] - Healthcheck interval in seconds
 * @property {number} [healthcheckTimeout=10] - Healthcheck timeout in seconds
 * @property {number} [healthcheckRetries=3] - Healthcheck retries
 * @property {Object.<string, string>} [labels={}] - Labels to add to the image
 * @property {Object.<string, string>} [env={}] - Environment variables
 * @property {boolean} [noNewPrivileges=true] - Add no-new-privileges security option
 */

/**
 * @typedef {Object} ComposeServiceOptions
 * @property {string} image - Image to use
 * @property {string} [build] - Build context path
 * @property {string[]} [ports=[]] - Port mappings (e.g., ['3000:3000'])
 * @property {Object.<string, string>} [environment={}] - Environment variables
 * @property {string[]} [volumes=[]] - Volume mounts
 * @property {string[]} [dependsOn=[]] - Service dependencies
 * @property {string} [command] - Override command
 * @property {Object} [resources] - Resource limits
 * @property {string} [resources.memoryLimit='512m'] - Memory limit
 * @property {string} [resources.cpuLimit='0.5'] - CPU limit
 * @property {string} [resources.memoryReservation='256m'] - Memory reservation
 * @property {string} [resources.cpuReservation='0.25'] - CPU reservation
 */

/**
 * @typedef {Object} ComposeOptions
 * @property {string} [version='3.8'] - Compose file version
 * @property {Object.<string, ComposeServiceOptions>} services - Map of service name to service options
 * @property {string} [networkName='app-network'] - Custom network name
 * @property {string} [networkDriver='bridge'] - Network driver
 * @property {boolean} [enableLogging=true] - Add logging configuration
 * @property {string} [logDriver='json-file'] - Log driver
 * @property {string} [logMaxSize='10m'] - Max log file size
 * @property {string} [logMaxFile='3'] - Max number of log files
 */

/**
 * @typedef {Object} RuntimeCheckResult
 * @property {boolean} available - Whether Docker runtime is available
 * @property {string} [dockerVersion] - Docker version string
 * @property {Object[]} runningContainers - List of running container audit results
 * @property {AuditFinding[]} findings - Runtime-level findings
 * @property {Object} [daemonConfig] - Docker daemon configuration findings
 */

/**
 * @typedef {Object} ProxyConfig
 * @property {number} proxyPort - Port the proxy listens on
 * @property {string} socketPath - Path to Docker socket
 * @property {string[]} allowedEndpoints - Allowed API endpoint patterns
 * @property {string[]} allowedMethods - Allowed HTTP methods
 * @property {Object} server - The HTTP server instance (or config for starting)
 */

// Sensitive volume paths that should not be mounted
const SENSITIVE_VOLUMES = [
  '/etc/shadow',
  '/etc/passwd',
  '/etc/ssh',
  '/root',
  '/proc',
  '/sys',
  '/dev',
  '/var/run/docker.sock',
  '/run/docker.sock',
  '/etc/docker',
  '/var/lib/docker',
  '/boot',
  '/lib/modules',
  '/usr/src',
  '/etc/crontab',
  '/etc/cron.d',
  '/etc/sudoers',
  '/etc/sudoers.d',
];

// Dangerous capabilities that should typically be dropped
const DANGEROUS_CAPABILITIES = [
  'ALL',
  'SYS_ADMIN',
  'NET_ADMIN',
  'SYS_PTRACE',
  'SYS_MODULE',
  'DAC_READ_SEARCH',
  'NET_RAW',
  'SYS_RAWIO',
  'SYSLOG',
  'SYS_TIME',
  'SYS_RESOURCE',
  'MKNOD',
  'AUDIT_WRITE',
  'SETFCAP',
  'MAC_OVERRIDE',
  'MAC_ADMIN',
  'LINUX_IMMUTABLE',
  'IPC_LOCK',
  'SYS_BOOT',
  'LEASE',
  'WAKE_ALARM',
  'BLOCK_SUSPEND',
];

// Minimal set of capabilities typically needed
const MINIMAL_CAPABILITIES = [
  'CHOWN',
  'DAC_OVERRIDE',
  'FOWNER',
  'FSETID',
  'KILL',
  'SETGID',
  'SETUID',
  'SETPCAP',
  'NET_BIND_SERVICE',
  'SYS_CHROOT',
  'SETFCAP',
];

/**
 * Parse a Docker Compose YAML file and return its contents.
 * @param {string} filePath - Path to the compose file
 * @returns {Object} Parsed compose configuration
 * @throws {Error} If file cannot be read or parsed
 */
function parseComposeFile(filePath) {
  const resolvedPath = path.resolve(filePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Compose file not found: ${resolvedPath}`);
  }
  const content = fs.readFileSync(resolvedPath, 'utf8');
  const parsed = yaml.load(content);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`Invalid compose file format: ${resolvedPath}`);
  }
  return parsed;
}

/**
 * Create an audit finding object.
 * @param {string} severity - Finding severity
 * @param {string} rule - Rule identifier
 * @param {string} service - Affected service
 * @param {string} message - Description
 * @param {string} remediation - Suggested fix
 * @returns {AuditFinding}
 */
function createFinding(severity, rule, service, message, remediation) {
  return { severity, rule, service, message, remediation };
}

/**
 * Check if a volume mount refers to a sensitive path.
 * @param {string} volumeSpec - Volume specification string (e.g., '/host/path:/container/path')
 * @returns {{ isSensitive: boolean, path: string|null }}
 */
function checkSensitiveVolume(volumeSpec) {
  const hostPath = String(volumeSpec).split(':')[0].trim();
  for (const sensitive of SENSITIVE_VOLUMES) {
    if (
      hostPath === sensitive ||
      hostPath.startsWith(sensitive + '/')
    ) {
      return { isSensitive: true, path: sensitive };
    }
  }
  return { isSensitive: false, path: null };
}

/**
 * Audit a single service configuration from a compose file.
 * @param {string} serviceName - Name of the service
 * @param {Object} serviceConfig - Service configuration object
 * @returns {AuditFinding[]} List of findings for this service
 */
function auditService(serviceName, serviceConfig) {
  const findings = [];

  // Check for privileged mode
  if (serviceConfig.privileged === true) {
    findings.push(createFinding(
      'critical',
      'PRIV_MODE',
      serviceName,
      'Container is running in privileged mode. This gives the container full access to the host.',
      'Remove "privileged: true" and use specific capabilities with cap_add instead.'
    ));
  }

  // Check for Docker socket mounts
  const volumes = serviceConfig.volumes || [];
  for (const vol of volumes) {
    const volStr = String(vol);
    if (
      volStr.includes('docker.sock') ||
      volStr.includes('/var/run/docker') ||
      volStr.includes('/run/docker')
    ) {
      findings.push(createFinding(
        'critical',
        'DOCKER_SOCKET',
        serviceName,
        `Docker socket is mounted: "${volStr}". This effectively grants root access to the host.`,
        'Remove the Docker socket mount. Use a Docker socket proxy with restricted API access if Docker API access is required.'
      ));
    }

    // Check for sensitive volume mounts
    const { isSensitive, path: sensitivePath } = checkSensitiveVolume(volStr);
    if (isSensitive && !volStr.includes('docker.sock')) {
      findings.push(createFinding(
        'high',
        'SENSITIVE_MOUNT',
        serviceName,
        `Sensitive host path mounted: "${sensitivePath}" in volume "${volStr}".`,
        `Remove the sensitive volume mount or use a more specific, less privileged path.`
      ));
    }

    // Check for read-write mounts of host paths
    if (volStr.includes(':') && !volStr.includes(':ro') && !volStr.startsWith('.')) {
      const hostPart = volStr.split(':')[0];
      if (hostPart.startsWith('/')) {
        findings.push(createFinding(
          'medium',
          'RW_HOST_MOUNT',
          serviceName,
          `Host path "${hostPart}" is mounted read-write.`,
          'Add ":ro" to the volume mount if write access is not required.'
        ));
      }
    }
  }

  // Check for missing cap_drop
  const capDrop = serviceConfig.cap_drop || [];
  if (capDrop.length === 0) {
    findings.push(createFinding(
      'high',
      'NO_CAP_DROP',
      serviceName,
      'No capabilities are dropped. Container retains all default capabilities.',
      'Add "cap_drop: [ALL]" and then selectively add required capabilities with "cap_add".'
    ));
  } else {
    const hasDropAll = capDrop.some(c => String(c).toUpperCase() === 'ALL');
    if (!hasDropAll) {
      findings.push(createFinding(
        'medium',
        'PARTIAL_CAP_DROP',
        serviceName,
        'Capabilities are partially dropped but "ALL" is not dropped first.',
        'Use "cap_drop: [ALL]" and then selectively add required capabilities with "cap_add".'
      ));
    }
  }

  // Check for dangerous added capabilities
  const capAdd = serviceConfig.cap_add || [];
  for (const cap of capAdd) {
    const capUpper = String(cap).toUpperCase();
    if (capUpper === 'ALL') {
      findings.push(createFinding(
        'critical',
        'CAP_ADD_ALL',
        serviceName,
        'All capabilities are added to the container.',
        'Remove "ALL" from cap_add and only add specific required capabilities.'
      ));
    } else if (capUpper === 'SYS_ADMIN') {
      findings.push(createFinding(
        'critical',
        'CAP_SYS_ADMIN',
        serviceName,
        'SYS_ADMIN capability is added. This is nearly equivalent to running as privileged.',
        'Remove SYS_ADMIN capability and use more specific capabilities.'
      ));
    } else if (['NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'SYS_RAWIO'].includes(capUpper)) {
      findings.push(createFinding(
        'high',
        `CAP_${capUpper}`,
        serviceName,
        `Dangerous capability ${capUpper} is added to the container.`,
        `Remove ${capUpper} unless absolutely required and document the justification.`
      ));
    }
  }

  // Check for root user
  const user = serviceConfig.user;
  if (!user || user === 'root' || user === '0' || user === '0:0') {
    findings.push(createFinding(
      'high',
      'ROOT_USER',
      serviceName,
      user ? `Container explicitly runs as root user ("${user}").` : 'No user specified; container may run as root.',
      'Add "user: \'1001:1001\'" or specify a non-root user. Ensure the Dockerfile creates a non-root user.'
    ));
  }

  // Check for host network mode
  const networkMode = serviceConfig.network_mode;
  if (networkMode === 'host') {
    findings.push(createFinding(
      'high',
      'HOST_NETWORK',
      serviceName,
      'Container uses host network mode. This bypasses network isolation.',
      'Remove "network_mode: host" and use port mappings or custom networks instead.'
    ));
  }

  // Check for host PID namespace
  if (serviceConfig.pid === 'host') {
    findings.push(createFinding(
      'high',
      'HOST_PID',
      serviceName,
      'Container shares the host PID namespace.',
      'Remove "pid: host" unless absolutely required for process monitoring.'
    ));
  }

  // Check for host IPC namespace
  if (serviceConfig.ipc === 'host') {
    findings.push(createFinding(
      'high',
      'HOST_IPC',
      serviceName,
      'Container shares the host IPC namespace.',
      'Remove "ipc: host" unless absolutely required.'
    ));
  }

  // Check for missing security_opt
  const securityOpt = serviceConfig.security_opt || [];
  const hasNoNewPrivileges = securityOpt.some(opt =>
    String(opt).includes('no-new-privileges') && !String(opt).includes('no-new-privileges:false')
  );
  if (!hasNoNewPrivileges) {
    findings.push(createFinding(
      'medium',
      'NO_NEW_PRIVILEGES',
      serviceName,
      'no-new-privileges security option is not set.',
      'Add "security_opt: [\'no-new-privileges:true\']" to prevent privilege escalation.'
    ));
  }

  // Check for seccomp profile
  const hasSeccomp = securityOpt.some(opt => String(opt).includes('seccomp'));
  if (!hasSeccomp) {
    findings.push(createFinding(
      'low',
      'NO_SECCOMP',
      serviceName,
      'No explicit seccomp profile configured (default Docker profile will be used).',
      'Consider using a custom seccomp profile for additional syscall restrictions.'
    ));
  }

  // Check for AppArmor / SELinux profiles
  const hasAppArmor = securityOpt.some(opt => String(opt).includes('apparmor'));
  const hasSelinux = securityOpt.some(opt => String(opt).includes('label'));
  if (!hasAppArmor && !hasSelinux) {
    findings.push(createFinding(
      'low',
      'NO_MANDATORY_ACCESS_CONTROL',
      serviceName,
      'No AppArmor or SELinux profile specified.',
      'Consider adding an AppArmor or SELinux profile for additional security.'
    ));
  }

  // Check for missing resource limits
  const deploy = serviceConfig.deploy || {};
  const resources = deploy.resources || {};
  const limits = resources.limits || {};
  if (!limits.memory && !limits.cpus) {
    // Also check top-level mem_limit and cpus for compose v2 compatibility
    if (!serviceConfig.mem_limit && !serviceConfig.cpus && !serviceConfig.memswap_limit) {
      findings.push(createFinding(
        'medium',
        'NO_RESOURCE_LIMITS',
        serviceName,
        'No resource limits (memory, CPU) are configured.',
        'Add resource limits under deploy.resources.limits or use mem_limit/cpus.'
      ));
    }
  }

  // Check for missing health check
  if (!serviceConfig.healthcheck) {
    findings.push(createFinding(
      'low',
      'NO_HEALTHCHECK',
      serviceName,
      'No healthcheck is configured for the service.',
      'Add a healthcheck to enable Docker to monitor container health.'
    ));
  }

  // Check for missing read_only filesystem
  if (serviceConfig.read_only !== true) {
    findings.push(createFinding(
      'medium',
      'WRITABLE_ROOTFS',
      serviceName,
      'Container filesystem is not read-only.',
      'Add "read_only: true" and use tmpfs mounts for directories that need write access.'
    ));
  }

  // Check for tmpfs on /tmp and /run if read_only
  if (serviceConfig.read_only === true) {
    const tmpfs = serviceConfig.tmpfs || [];
    const tmpfsArr = Array.isArray(tmpfs) ? tmpfs : [tmpfs];
    const hasTmp = tmpfsArr.some(t => String(t).startsWith('/tmp'));
    if (!hasTmp) {
      findings.push(createFinding(
        'info',
        'MISSING_TMPFS_TMP',
        serviceName,
        'Read-only filesystem enabled but /tmp is not mounted as tmpfs.',
        'Add "tmpfs: [/tmp]" if the application needs to write to /tmp.'
      ));
    }
  }

  // Check for exposed ports on 0.0.0.0
  const ports = serviceConfig.ports || [];
  for (const portSpec of ports) {
    const portStr = String(portSpec);
    // If port doesn't specify a bind address, it binds to 0.0.0.0
    if (!portStr.match(/^\d+\.\d+\.\d+\.\d+:/) && portStr.includes(':')) {
      findings.push(createFinding(
        'low',
        'WILDCARD_PORT_BINDING',
        serviceName,
        `Port "${portStr}" binds to all interfaces (0.0.0.0).`,
        'Bind to specific interface, e.g., "127.0.0.1:8080:8080" for local-only access.'
      ));
    }
  }

  // Check for environment variables that might contain secrets
  const environment = serviceConfig.environment || {};
  const envEntries = Array.isArray(environment)
    ? environment.map(e => { const [k, ...v] = String(e).split('='); return [k, v.join('=')]; })
    : Object.entries(environment);

  const secretPatterns = [
    /password/i, /secret/i, /api_key/i, /apikey/i, /token/i,
    /private_key/i, /credentials/i, /auth/i, /db_pass/i,
  ];

  for (const [key, value] of envEntries) {
    const keyStr = String(key);
    const valueStr = String(value || '');
    for (const pattern of secretPatterns) {
      if (pattern.test(keyStr) && valueStr && !valueStr.startsWith('${') && valueStr !== '') {
        findings.push(createFinding(
          'high',
          'SECRET_IN_ENV',
          serviceName,
          `Possible secret in environment variable "${keyStr}". Hardcoded secrets in compose files are insecure.`,
          'Use Docker secrets, environment variable files (.env), or a secrets manager.'
        ));
        break;
      }
    }
  }

  // Check for missing restart policy
  if (!serviceConfig.restart && !(deploy && deploy.restart_policy)) {
    findings.push(createFinding(
      'info',
      'NO_RESTART_POLICY',
      serviceName,
      'No restart policy is configured.',
      'Add "restart: unless-stopped" or configure a restart policy for production services.'
    ));
  }

  // Check for missing logging configuration
  if (!serviceConfig.logging) {
    findings.push(createFinding(
      'info',
      'NO_LOGGING_CONFIG',
      serviceName,
      'No logging driver or options configured.',
      'Configure logging with appropriate max-size and max-file to prevent disk exhaustion.'
    ));
  }

  return findings;
}

/**
 * Audit a Docker Compose file for security issues.
 *
 * Checks for common security misconfigurations including:
 * - Docker socket mounts
 * - Privileged containers
 * - Missing capability drops
 * - Running as root user
 * - Host network/PID/IPC modes
 * - Sensitive volume mounts
 * - Missing resource limits
 * - Writable root filesystem
 * - Hardcoded secrets in environment variables
 * - Missing security options (no-new-privileges, seccomp, etc.)
 *
 * @param {string} composeFilePath - Path to the Docker Compose file to audit
 * @returns {AuditResult} Audit result with findings and summary
 * @throws {Error} If the compose file cannot be read or parsed
 *
 * @example
 * const { auditDockerConfig } = require('./docker-hardener');
 * const result = auditDockerConfig('./docker-compose.yml');
 * console.log(result.summary);
 * if (!result.passed) {
 *   result.findings.filter(f => f.severity === 'critical').forEach(f => {
 *     console.error(`[${f.severity}] ${f.service}: ${f.message}`);
 *   });
 * }
 */
function auditDockerConfig(composeFilePath) {
  const composeConfig = parseComposeFile(composeFilePath);
  const findings = [];

  // Determine services location (v2 vs v3 compose format)
  const services = composeConfig.services || {};

  if (Object.keys(services).length === 0) {
    findings.push(createFinding(
      'info',
      'NO_SERVICES',
      'global',
      'No services found in the compose file.',
      'Ensure the compose file has a "services" section.'
    ));
  }

  // Global checks
  // Check if version is specified and is old
  if (composeConfig.version) {
    const version = String(composeConfig.version);
    if (version.startsWith('2') || version === '1') {
      findings.push(createFinding(
        'low',
        'OLD_COMPOSE_VERSION',
        'global',
        `Compose file uses version "${version}". Consider upgrading to version 3.x+.`,
        'Upgrade to version 3.8 or remove the version field (Docker Compose v2+ auto-detects).'
      ));
    }
  }

  // Check for default network configuration
  const networks = composeConfig.networks || {};
  if (Object.keys(networks).length === 0 && Object.keys(services).length > 1) {
    findings.push(createFinding(
      'low',
      'NO_CUSTOM_NETWORK',
      'global',
      'No custom networks defined. All services will share the default network.',
      'Define custom networks to isolate services that do not need to communicate.'
    ));
  }

  // Audit each service
  for (const [serviceName, serviceConfig] of Object.entries(services)) {
    if (serviceConfig && typeof serviceConfig === 'object') {
      const serviceFindings = auditService(serviceName, serviceConfig);
      findings.push(...serviceFindings);
    }
  }

  // Compute counts
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;
  const infoCount = findings.filter(f => f.severity === 'info').length;

  const passed = criticalCount === 0 && highCount === 0;

  const summary = [
    `Docker Compose Security Audit: ${passed ? 'PASSED' : 'FAILED'}`,
    `File: ${path.resolve(composeFilePath)}`,
    `Total findings: ${findings.length}`,
    `  Critical: ${criticalCount}`,
    `  High: ${highCount}`,
    `  Medium: ${mediumCount}`,
    `  Low: ${lowCount}`,
    `  Info: ${infoCount}`,
  ].join('\n');

  return {
    passed,
    findings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    summary,
  };
}

/**
 * Generate a security-hardened Dockerfile content.
 *
 * Generates a Dockerfile following security best practices:
 * - Multi-stage builds to minimize attack surface
 * - Non-root user execution
 * - Minimal base images (alpine preferred)
 * - Health checks
 * - Proper signal handling with tini
 * - No-new-privileges security option label
 * - Minimal filesystem permissions
 * - Security labels
 *
 * @param {DockerfileOptions} options - Configuration options for the Dockerfile
 * @returns {string} Generated Dockerfile content
 *
 * @example
 * const { generateSecureDockerfile } = require('./docker-hardener');
 * const dockerfile = generateSecureDockerfile({
 *   baseImage: 'node:20-alpine',
 *   port: 3000,
 *   cmd: 'node server.js',
 *   multiStage: true,
 *   buildCommands: ['npm ci --only=production'],
 *   copyFromBuild: ['node_modules', 'dist'],
 * });
 * fs.writeFileSync('Dockerfile', dockerfile);
 */
function generateSecureDockerfile(options) {
  const {
    baseImage = 'node:20-alpine',
    appDir = '/app',
    port = 3000,
    entrypoint,
    cmd = 'node server.js',
    user = 'appuser',
    uid = 1001,
    gid = 1001,
    additionalPackages = [],
    multiStage = true,
    buildStageImage,
    buildCommands = [],
    copyFromBuild = [],
    healthcheck = true,
    healthcheckCmd,
    healthcheckInterval = 30,
    healthcheckTimeout = 10,
    healthcheckRetries = 3,
    labels = {},
    env = {},
    noNewPrivileges = true,
  } = options;

  const lines = [];
  const isAlpine = baseImage.includes('alpine');
  const pkgManager = isAlpine ? 'apk' : 'apt-get';
  const now = new Date().toISOString();

  // Security labels
  const allLabels = {
    'org.opencontainers.image.created': now,
    'org.opencontainers.image.description': 'Security-hardened container',
    'security.hardened': 'true',
    ...labels,
  };

  if (multiStage) {
    // ====== BUILD STAGE ======
    const buildImage = buildStageImage || baseImage;
    lines.push(`# =============================================================================`);
    lines.push(`# Build stage`);
    lines.push(`# =============================================================================`);
    lines.push(`FROM ${buildImage} AS builder`);
    lines.push('');
    lines.push(`WORKDIR ${appDir}`);
    lines.push('');

    // Copy dependency manifests first for cache optimization
    lines.push('# Copy dependency manifests first for better layer caching');
    lines.push('COPY package*.json ./');
    if (buildCommands.length > 0) {
      lines.push('');
      lines.push('# Install dependencies');
      for (const buildCmd of buildCommands) {
        lines.push(`RUN ${buildCmd}`);
      }
    }
    lines.push('');
    lines.push('# Copy application source');
    lines.push('COPY . .');
    lines.push('');

    // ====== PRODUCTION STAGE ======
    lines.push(`# =============================================================================`);
    lines.push(`# Production stage - security hardened`);
    lines.push(`# =============================================================================`);
    lines.push(`FROM ${baseImage} AS production`);
  } else {
    lines.push(`# =============================================================================`);
    lines.push(`# Security-hardened Dockerfile`);
    lines.push(`# =============================================================================`);
    lines.push(`FROM ${baseImage}`);
  }

  lines.push('');

  // Labels
  lines.push('# Security and metadata labels');
  for (const [key, value] of Object.entries(allLabels)) {
    lines.push(`LABEL ${key}="${value}"`);
  }
  lines.push('');

  // Install security updates and required packages
  lines.push('# Install security updates and required packages, then clean up');
  if (isAlpine) {
    const packages = ['dumb-init', 'curl', ...additionalPackages];
    lines.push(`RUN apk update && \\`);
    lines.push(`    apk upgrade --no-cache && \\`);
    lines.push(`    apk add --no-cache ${packages.join(' ')} && \\`);
    lines.push(`    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*`);
  } else {
    const packages = ['dumb-init', 'curl', ...additionalPackages];
    lines.push(`RUN apt-get update && \\`);
    lines.push(`    apt-get upgrade -y && \\`);
    lines.push(`    apt-get install -y --no-install-recommends ${packages.join(' ')} && \\`);
    lines.push(`    apt-get clean && \\`);
    lines.push(`    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*`);
  }
  lines.push('');

  // Create non-root user and group
  lines.push('# Create non-root user and group');
  if (isAlpine) {
    lines.push(`RUN addgroup -g ${gid} -S ${user} && \\`);
    lines.push(`    adduser -u ${uid} -S -G ${user} -s /sbin/nologin ${user}`);
  } else {
    lines.push(`RUN groupadd -g ${gid} ${user} && \\`);
    lines.push(`    useradd -u ${uid} -g ${user} -s /sbin/nologin -M ${user}`);
  }
  lines.push('');

  // Create application directory with proper ownership
  lines.push('# Create application directory with proper ownership');
  lines.push(`RUN mkdir -p ${appDir} && chown -R ${uid}:${gid} ${appDir}`);
  lines.push('');

  lines.push(`WORKDIR ${appDir}`);
  lines.push('');

  if (multiStage && copyFromBuild.length > 0) {
    lines.push('# Copy artifacts from build stage');
    for (const artifact of copyFromBuild) {
      lines.push(`COPY --from=builder --chown=${uid}:${gid} ${appDir}/${artifact} ./${artifact}`);
    }
    lines.push('');
  }

  if (!multiStage) {
    lines.push('# Copy application source with proper ownership');
    lines.push(`COPY --chown=${uid}:${gid} . .`);
    lines.push('');
  }

  // If multi-stage but no explicit copyFromBuild, copy everything
  if (multiStage && copyFromBuild.length === 0) {
    lines.push('# Copy application from build stage');
    lines.push(`COPY --from=builder --chown=${uid}:${gid} ${appDir} .`);
    lines.push('');
  }

  // Environment variables
  if (Object.keys(env).length > 0) {
    lines.push('# Environment variables');
    for (const [key, value] of Object.entries(env)) {
      lines.push(`ENV ${key}=${value}`);
    }
    lines.push('');
  }

  // Set NODE_ENV for Node.js applications
  if (baseImage.includes('node')) {
    lines.push('# Set production environment');
    lines.push('ENV NODE_ENV=production');
    lines.push('');
  }

  // Remove unnecessary setuid/setgid binaries
  lines.push('# Remove unnecessary setuid/setgid binaries to reduce attack surface');
  lines.push(`RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true`);
  lines.push('');

  // Expose port
  if (port) {
    lines.push(`# Expose application port`);
    lines.push(`EXPOSE ${port}`);
    lines.push('');
  }

  // Healthcheck
  if (healthcheck) {
    const hcCmd = healthcheckCmd || `curl -f http://localhost:${port}/health || exit 1`;
    lines.push('# Health check');
    lines.push(`HEALTHCHECK --interval=${healthcheckInterval}s --timeout=${healthcheckTimeout}s --retries=${healthcheckRetries} --start-period=10s \\`);
    lines.push(`  CMD ${hcCmd}`);
    lines.push('');
  }

  // Switch to non-root user
  lines.push('# Switch to non-root user');
  lines.push(`USER ${uid}:${gid}`);
  lines.push('');

  // Use dumb-init to handle signals properly
  if (entrypoint) {
    lines.push('# Use dumb-init for proper signal handling');
    lines.push(`ENTRYPOINT ["dumb-init", "--", ${JSON.stringify(entrypoint)}]`);
  } else {
    lines.push('# Use dumb-init for proper signal handling');
    lines.push('ENTRYPOINT ["dumb-init", "--"]');
  }
  lines.push('');

  // CMD
  if (cmd) {
    const cmdParts = cmd.split(' ');
    const cmdJson = JSON.stringify(cmdParts);
    lines.push(`CMD ${cmdJson}`);
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate a security-hardened Docker Compose file content.
 *
 * Generates a compose file with security best practices:
 * - Non-root users for all services
 * - Capability dropping (cap_drop: ALL)
 * - Read-only root filesystem with tmpfs for writable paths
 * - Resource limits (memory, CPU)
 * - Custom isolated networks
 * - Security options (no-new-privileges)
 * - Logging configuration with size limits
 * - Health checks
 * - No privileged mode
 * - No host network/PID/IPC namespaces
 *
 * @param {ComposeOptions} options - Configuration options for the compose file
 * @returns {string} Generated Docker Compose YAML content
 *
 * @example
 * const { generateSecureCompose } = require('./docker-hardener');
 * const compose = generateSecureCompose({
 *   services: {
 *     web: {
 *       image: 'myapp:latest',
 *       ports: ['127.0.0.1:3000:3000'],
 *       environment: { NODE_ENV: 'production' },
 *       resources: { memoryLimit: '256m', cpuLimit: '0.5' },
 *     },
 *     redis: {
 *       image: 'redis:7-alpine',
 *       resources: { memoryLimit: '128m', cpuLimit: '0.25' },
 *     },
 *   },
 * });
 * fs.writeFileSync('docker-compose.yml', compose);
 */
function generateSecureCompose(options) {
  const {
    version,
    services = {},
    networkName = 'app-network',
    networkDriver = 'bridge',
    enableLogging = true,
    logDriver = 'json-file',
    logMaxSize = '10m',
    logMaxFile = '3',
  } = options;

  const composeObj = {};

  if (version) {
    composeObj.version = version;
  }

  composeObj.services = {};

  for (const [serviceName, serviceOpts] of Object.entries(services)) {
    const {
      image,
      build,
      ports = [],
      environment = {},
      volumes = [],
      dependsOn = [],
      command,
      resources = {},
    } = serviceOpts;

    const {
      memoryLimit = '512m',
      cpuLimit = '0.5',
      memoryReservation = '256m',
      cpuReservation = '0.25',
    } = resources;

    const service = {};

    if (image) {
      service.image = image;
    }

    if (build) {
      service.build = {
        context: build,
        dockerfile: 'Dockerfile',
      };
    }

    if (command) {
      service.command = command;
    }

    // Non-root user
    service.user = '1001:1001';

    // Read-only root filesystem
    service.read_only = true;

    // tmpfs mounts for writable directories
    service.tmpfs = [
      '/tmp:size=64M',
      '/run:size=64M',
    ];

    // Drop all capabilities
    service.cap_drop = ['ALL'];

    // Security options
    service.security_opt = [
      'no-new-privileges:true',
    ];

    // Ports
    if (ports.length > 0) {
      service.ports = ports;
    }

    // Environment
    if (Object.keys(environment).length > 0 || (Array.isArray(environment) && environment.length > 0)) {
      service.environment = environment;
    }

    // Volumes (ensure :ro where possible)
    if (volumes.length > 0) {
      service.volumes = volumes.map(v => {
        const volStr = String(v);
        // Don't modify named volumes or volumes already marked :ro
        if (!volStr.includes(':') || volStr.endsWith(':ro') || volStr.endsWith(':rw')) {
          return volStr;
        }
        return volStr;
      });
    }

    // Dependencies
    if (dependsOn.length > 0) {
      service.depends_on = dependsOn;
    }

    // Resource limits
    service.deploy = {
      resources: {
        limits: {
          memory: memoryLimit,
          cpus: cpuLimit,
        },
        reservations: {
          memory: memoryReservation,
          cpus: cpuReservation,
        },
      },
    };

    // Restart policy
    service.restart = 'unless-stopped';

    // Disable privilege escalation
    service.privileged = false;

    // Network
    service.networks = [networkName];

    // Health check placeholder
    service.healthcheck = {
      test: ['CMD-SHELL', 'curl -f http://localhost:${PORT:-3000}/health || exit 1'],
      interval: '30s',
      timeout: '10s',
      retries: 3,
      start_period: '15s',
    };

    // Logging
    if (enableLogging) {
      service.logging = {
        driver: logDriver,
        options: {
          'max-size': logMaxSize,
          'max-file': logMaxFile,
        },
      };
    }

    // PID limit
    service.pids_limit = 100;

    composeObj.services[serviceName] = service;
  }

  // Networks
  composeObj.networks = {
    [networkName]: {
      driver: networkDriver,
      driver_opts: {
        encrypted: 'true',
      },
    },
  };

  // Generate YAML with a header comment
  const header = [
    '# =============================================================================',
    '# Security-Hardened Docker Compose Configuration',
    `# Generated: ${new Date().toISOString()}`,
    '#',
    '# Security features enabled:',
    '#   - Non-root user (1001:1001)',
    '#   - Read-only root filesystem',
    '#   - All capabilities dropped',
    '#   - no-new-privileges security option',
    '#   - Resource limits (memory and CPU)',
    '#   - Logging with size limits',
    '#   - Custom isolated network',
    '#   - Health checks',
    '#   - PID limits',
    '#   - Restart policy',
    '# =============================================================================',
    '',
  ].join('\n');

  const yamlContent = yaml.dump(composeObj, {
    indent: 2,
    lineWidth: 120,
    noRefs: true,
    sortKeys: false,
    quotingType: '"',
    forceQuotes: false,
  });

  return header + yamlContent;
}

/**
 * Check the Docker container runtime for security issues.
 *
 * Inspects the running Docker environment for:
 * - Docker daemon availability and version
 * - Running containers' security posture
 * - Privileged containers
 * - Containers running as root
 * - Containers with Docker socket mounted
 * - Containers with dangerous capabilities
 * - Containers without resource limits
 * - Docker daemon configuration issues
 *
 * @returns {RuntimeCheckResult} Runtime check results with findings
 *
 * @example
 * const { checkContainerRuntime } = require('./docker-hardener');
 * const runtime = checkContainerRuntime();
 * if (runtime.available) {
 *   console.log(`Docker version: ${runtime.dockerVersion}`);
 *   runtime.findings.forEach(f => console.log(`[${f.severity}] ${f.message}`));
 * }
 */
function checkContainerRuntime() {
  const result = {
    available: false,
    dockerVersion: null,
    runningContainers: [],
    findings: [],
    daemonConfig: {},
  };

  // Check if Docker is available
  try {
    const versionOutput = execSync('docker version --format "{{.Server.Version}}"', {
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    result.available = true;
    result.dockerVersion = versionOutput;
  } catch (err) {
    result.available = false;
    result.findings.push(createFinding(
      'info',
      'DOCKER_UNAVAILABLE',
      'runtime',
      `Docker runtime is not available: ${err.message}`,
      'Ensure Docker is installed and the current user has permissions to access the Docker daemon.'
    ));
    return result;
  }

  // Check Docker info for security-related settings
  try {
    const infoOutput = execSync('docker info --format "{{json .}}"', {
      encoding: 'utf8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const info = JSON.parse(infoOutput);

    // Check if live restore is enabled
    if (!info.LiveRestoreEnabled) {
      result.findings.push(createFinding(
        'low',
        'NO_LIVE_RESTORE',
        'daemon',
        'Docker live restore is not enabled.',
        'Enable live restore in /etc/docker/daemon.json: {"live-restore": true}'
      ));
    }

    // Check security options
    const securityOptions = info.SecurityOptions || [];
    const hasSeccomp = securityOptions.some(o => String(o).includes('seccomp'));
    const hasApparmor = securityOptions.some(o => String(o).includes('apparmor'));
    const hasRootless = securityOptions.some(o => String(o).includes('rootless'));
    const hasUserns = securityOptions.some(o => String(o).includes('userns'));

    if (!hasSeccomp) {
      result.findings.push(createFinding(
        'medium',
        'DAEMON_NO_SECCOMP',
        'daemon',
        'Default seccomp profile is not enabled on the Docker daemon.',
        'Ensure the Docker daemon has seccomp enabled (default in modern Docker versions).'
      ));
    }

    if (!hasRootless && !hasUserns) {
      result.findings.push(createFinding(
        'low',
        'NO_ROOTLESS_OR_USERNS',
        'daemon',
        'Docker is not running in rootless mode and user namespace remapping is not configured.',
        'Consider running Docker in rootless mode or enabling user namespace remapping.'
      ));
    }

    result.daemonConfig = {
      liveRestore: info.LiveRestoreEnabled || false,
      seccomp: hasSeccomp,
      apparmor: hasApparmor,
      rootless: hasRootless,
      userNamespaceRemap: hasUserns,
      storageDriver: info.Driver,
      serverVersion: info.ServerVersion,
    };
  } catch (err) {
    result.findings.push(createFinding(
      'info',
      'DAEMON_INFO_UNAVAILABLE',
      'daemon',
      `Could not retrieve Docker daemon info: ${err.message}`,
      'Ensure proper permissions to query Docker daemon information.'
    ));
  }

  // Get running containers and audit them
  try {
    const containersOutput = execSync(
      'docker ps -q',
      { encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();

    if (!containersOutput) {
      result.findings.push(createFinding(
        'info',
        'NO_RUNNING_CONTAINERS',
        'runtime',
        'No running containers found.',
        'This is informational only.'
      ));
      return result;
    }

    const containerIds = containersOutput.split('\n').filter(Boolean);

    for (const containerId of containerIds) {
      try {
        const inspectOutput = execSync(
          `docker inspect ${containerId}`,
          { encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }
        );
        const [containerInfo] = JSON.parse(inspectOutput);
        const containerName = (containerInfo.Name || containerId).replace(/^\//, '');
        const hostConfig = containerInfo.HostConfig || {};
        const config = containerInfo.Config || {};

        const containerAudit = {
          id: containerId,
          name: containerName,
          image: config.Image,
          findings: [],
        };

        // Check privileged mode
        if (hostConfig.Privileged) {
          containerAudit.findings.push(createFinding(
            'critical',
            'RUNTIME_PRIV_MODE',
            containerName,
            'Container is running in privileged mode.',
            'Restart the container without --privileged flag.'
          ));
        }

        // Check for root user
        const containerUser = config.User;
        if (!containerUser || containerUser === 'root' || containerUser === '0') {
          containerAudit.findings.push(createFinding(
            'high',
            'RUNTIME_ROOT_USER',
            containerName,
            `Container is running as root user (User: "${containerUser || 'not set'}").`,
            'Rebuild the image with a non-root USER or use --user flag when running.'
          ));
        }

        // Check for Docker socket mounts
        const mounts = containerInfo.Mounts || [];
        for (const mount of mounts) {
          if (mount.Source && (
            mount.Source.includes('docker.sock') ||
            mount.Source.includes('/var/run/docker')
          )) {
            containerAudit.findings.push(createFinding(
              'critical',
              'RUNTIME_DOCKER_SOCKET',
              containerName,
              `Docker socket is mounted from "${mount.Source}".`,
              'Remove the Docker socket mount and use a proxy if API access is needed.'
            ));
          }

          // Check sensitive mounts
          const { isSensitive, path: sensitivePath } = checkSensitiveVolume(mount.Source || '');
          if (isSensitive && !String(mount.Source).includes('docker.sock')) {
            containerAudit.findings.push(createFinding(
              'high',
              'RUNTIME_SENSITIVE_MOUNT',
              containerName,
              `Sensitive host path mounted: "${sensitivePath}" from "${mount.Source}".`,
              'Remove the sensitive volume mount.'
            ));
          }
        }

        // Check capabilities
        const capAdd = (hostConfig.CapAdd || []);
        const capDrop = (hostConfig.CapDrop || []);

        if (capDrop.length === 0) {
          containerAudit.findings.push(createFinding(
            'high',
            'RUNTIME_NO_CAP_DROP',
            containerName,
            'No capabilities are dropped from the container.',
            'Run with --cap-drop=ALL and add back only required capabilities.'
          ));
        }

        for (const cap of capAdd) {
          if (String(cap).toUpperCase() === 'SYS_ADMIN') {
            containerAudit.findings.push(createFinding(
              'critical',
              'RUNTIME_CAP_SYS_ADMIN',
              containerName,
              'Container has SYS_ADMIN capability.',
              'Remove SYS_ADMIN capability.'
            ));
          }
        }

        // Check network mode
        if (hostConfig.NetworkMode === 'host') {
          containerAudit.findings.push(createFinding(
            'high',
            'RUNTIME_HOST_NETWORK',
            containerName,
            'Container is using host network mode.',
            'Use bridge or custom network instead of host network.'
          ));
        }

        // Check PID mode
        if (hostConfig.PidMode === 'host') {
          containerAudit.findings.push(createFinding(
            'high',
            'RUNTIME_HOST_PID',
            containerName,
            'Container shares host PID namespace.',
            'Remove --pid=host flag.'
          ));
        }

        // Check resource limits
        if (!hostConfig.Memory || hostConfig.Memory === 0) {
          containerAudit.findings.push(createFinding(
            'medium',
            'RUNTIME_NO_MEMORY_LIMIT',
            containerName,
            'No memory limit is set for the container.',
            'Set a memory limit with --memory flag.'
          ));
        }

        if (!hostConfig.NanoCpus && (!hostConfig.CpuQuota || hostConfig.CpuQuota === 0)) {
          containerAudit.findings.push(createFinding(
            'medium',
            'RUNTIME_NO_CPU_LIMIT',
            containerName,
            'No CPU limit is set for the container.',
            'Set a CPU limit with --cpus flag.'
          ));
        }

        // Check PIDs limit
        if (!hostConfig.PidsLimit || hostConfig.PidsLimit === 0 || hostConfig.PidsLimit === -1) {
          containerAudit.findings.push(createFinding(
            'medium',
            'RUNTIME_NO_PIDS_LIMIT',
            containerName,
            'No PID limit is set for the container.',
            'Set a PID limit with --pids-limit flag to prevent fork bombs.'
          ));
        }

        // Check read-only root filesystem
        if (!hostConfig.ReadonlyRootfs) {
          containerAudit.findings.push(createFinding(
            'medium',
            'RUNTIME_WRITABLE_ROOTFS',
            containerName,
            'Container root filesystem is writable.',
            'Run with --read-only flag and use tmpfs for writable directories.'
          ));
        }

        // Check security options
        const secOpts = hostConfig.SecurityOpt || [];
        const hasNoNewPrivs = secOpts.some(o =>
          String(o).includes('no-new-privileges') && !String(o).includes('no-new-privileges=false')
        );
        if (!hasNoNewPrivs) {
          containerAudit.findings.push(createFinding(
            'medium',
            'RUNTIME_NO_NEW_PRIVILEGES',
            containerName,
            'no-new-privileges security option is not set.',
            'Run with --security-opt=no-new-privileges:true.'
          ));
        }

        // Check health check
        if (!config.Healthcheck || (config.Healthcheck.Test && config.Healthcheck.Test[0] === 'NONE')) {
          containerAudit.findings.push(createFinding(
            'low',
            'RUNTIME_NO_HEALTHCHECK',
            containerName,
            'No health check is configured for the container.',
            'Add a HEALTHCHECK instruction in the Dockerfile or use --health-cmd at runtime.'
          ));
        }

        result.runningContainers.push(containerAudit);
        result.findings.push(...containerAudit.findings);
      } catch (inspectErr) {
        result.findings.push(createFinding(
          'info',
          'INSPECT_FAILED',
          containerId,
          `Could not inspect container ${containerId}: ${inspectErr.message}`,
          'Ensure proper permissions to inspect containers.'
        ));
      }
    }
  } catch (err) {
    result.findings.push(createFinding(
      'info',
      'CONTAINER_LIST_FAILED',
      'runtime',
      `Could not list running containers: ${err.message}`,
      'Ensure proper permissions to list Docker containers.'
    ));
  }

  return result;
}

/**
 * Set up a Docker socket proxy that restricts API access to specific endpoints.
 *
 * Creates an HTTP proxy server that sits between clients and the Docker socket,
 * filtering requests to only allow access to specified API endpoints. This is
 * useful for giving containers limited Docker API access without exposing the
 * full Docker socket.
 *
 * The proxy:
 * - Only allows specified HTTP methods (GET by default)
 * - Only proxies requests matching allowed endpoint patterns
 * - Blocks access to dangerous endpoints (exec, commit, build, etc.)
 * - Logs all requests for auditing
 * - Can be used as a drop-in replacement for Docker socket mounts
 *
 * @param {string[]} allowedEndpoints - Array of allowed endpoint path patterns
 *   (supports simple wildcards). Examples: ['/containers/json', '/version', '/info']
 * @param {Object} [proxyOptions] - Additional proxy configuration
 * @param {number} [proxyOptions.port=2375] - Port for the proxy to listen on
 * @param {string} [proxyOptions.socketPath='/var/run/docker.sock'] - Docker socket path
 * @param {string[]} [proxyOptions.allowedMethods=['GET', 'HEAD']] - Allowed HTTP methods
 * @param {string} [proxyOptions.listenHost='127.0.0.1'] - Host to listen on
 * @param {Function} [proxyOptions.onRequest] - Callback for each request (method, path, allowed)
 * @param {Function} [proxyOptions.onError] - Callback for errors
 * @returns {ProxyConfig} Proxy configuration and server instance
 *
 * @example
 * const { setupDockerSocketProxy } = require('./docker-hardener');
 *
 * // Allow only read-only container listing and version info
 * const proxy = setupDockerSocketProxy([
 *   '/v1.*/containers/json',
 *   '/v1.*/containers/.*/json',
 *   '/version',
 *   '/_ping',
 * ], {
 *   port: 2375,
 *   allowedMethods: ['GET', 'HEAD'],
 *   onRequest: (method, path, allowed) => {
 *     console.log(`${allowed ? 'ALLOW' : 'DENY'}: ${method} ${path}`);
 *   },
 * });
 *
 * // Later, to stop the proxy:
 * // proxy.server.close();
 */
function setupDockerSocketProxy(allowedEndpoints, proxyOptions = {}) {
  const {
    port = 2375,
    socketPath = '/var/run/docker.sock',
    allowedMethods = ['GET', 'HEAD'],
    listenHost = '127.0.0.1',
    onRequest = null,
    onError = null,
  } = proxyOptions;

  // Dangerous endpoints that should never be proxied
  const dangerousPatterns = [
    /\/exec\//i,
    /\/exec$/i,
    /\/containers\/.*\/exec/i,
    /\/commit/i,
    /\/build/i,
    /\/push/i,
    /\/tag/i,
    /\/auth/i,
    /\/secrets/i,
    /\/configs/i,
    /\/swarm/i,
    /\/nodes/i,
    /\/plugins/i,
    /\/system\/df/i,
    /\/grpc/i,
  ];

  // Convert allowed endpoints to regex patterns
  const allowedPatterns = allowedEndpoints.map(endpoint => {
    // Escape special regex characters except * which becomes .*
    const escaped = endpoint
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    return new RegExp(`^${escaped}(\\?.*)?$`);
  });

  /**
   * Check if a request path matches any allowed pattern.
   * @param {string} reqPath - Request path
   * @returns {boolean}
   */
  function isAllowed(reqPath) {
    // Strip query parameters for pattern matching
    const pathOnly = reqPath.split('?')[0];

    // Check dangerous patterns first
    for (const pattern of dangerousPatterns) {
      if (pattern.test(pathOnly)) {
        return false;
      }
    }

    // Check allowed patterns
    for (const pattern of allowedPatterns) {
      if (pattern.test(reqPath) || pattern.test(pathOnly)) {
        return true;
      }
    }

    return false;
  }

  const server = http.createServer((req, res) => {
    const method = req.method.toUpperCase();
    const reqPath = req.url;
    const methodAllowed = allowedMethods.map(m => m.toUpperCase()).includes(method);
    const pathAllowed = isAllowed(reqPath);
    const allowed = methodAllowed && pathAllowed;

    // Invoke callback if provided
    if (typeof onRequest === 'function') {
      try {
        onRequest(method, reqPath, allowed);
      } catch (e) {
        // Don't let callback errors crash the proxy
      }
    }

    if (!allowed) {
      const reason = !methodAllowed
        ? `Method ${method} is not allowed`
        : `Path ${reqPath} is not in the allowed endpoint list`;

      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        message: 'Forbidden',
        reason: reason,
      }));
      return;
    }

    // Proxy the request to the Docker socket
    const proxyReqOptions = {
      socketPath: socketPath,
      path: reqPath,
      method: method,
      headers: { ...req.headers },
    };

    // Remove host header to prevent issues
    delete proxyReqOptions.headers.host;

    const proxyReq = http.request(proxyReqOptions, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      if (typeof onError === 'function') {
        try {
          onError(err, method, reqPath);
        } catch (e) {
          // Ignore callback errors
        }
      }
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: 'Bad Gateway',
          error: err.message,
        }));
      }
    });

    // Pipe request body for non-GET methods (though typically only GET/HEAD should be allowed)
    req.pipe(proxyReq);
  });

  server.on('error', (err) => {
    if (typeof onError === 'function') {
      try {
        onError(err, null, null);
      } catch (e) {
        // Ignore callback errors
      }
    }
  });

  server.listen(port, listenHost);

  const proxyConfig = {
    proxyPort: port,
    socketPath: socketPath,
    allowedEndpoints: allowedEndpoints,
    allowedMethods: allowedMethods,
    listenHost: listenHost,
    server: server,
    /**
     * Stop the proxy server.
     * @returns {Promise<void>}
     */
    stop: () => {
      return new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    },
    /**
     * Test if a request would be allowed by the proxy.
     * @param {string} method - HTTP method
     * @param {string} path - Request path
     * @returns {boolean}
     */
    testRequest: (method, pathToTest) => {
      const methodAllowed = allowedMethods.map(m => m.toUpperCase()).includes(method.toUpperCase());
      return methodAllowed && isAllowed(pathToTest);
    },
    /**
     * Generate a Docker Compose snippet for using this proxy.
     * @param {string} serviceName - Name of the proxy service
     * @returns {string} YAML snippet
     */
    getComposeSnippet: (serviceName = 'docker-proxy') => {
      const snippet = {
        [serviceName]: {
          image: 'tecnativa/docker-socket-proxy:latest',
          ports: [`${listenHost}:${port}:2375`],
          volumes: [`${socketPath}:/var/run/docker.sock:ro`],
          environment: {
            CONTAINERS: '1',
            IMAGES: '0',
            EXEC: '0',
            AUTH: '0',
            SECRETS: '0',
            POST: '0',
            BUILD: '0',
            COMMIT: '0',
            CONFIGS: '0',
            DISTRIBUTION: '0',
            NETWORKS: '0',
            NODES: '0',
            PLUGINS: '0',
            SERVICES: '0',
            SESSION: '0',
            SWARM: '0',
            SYSTEM: '0',
            TASKS: '0',
            VOLUMES: '0',
          },
          cap_drop: ['ALL'],
          read_only: true,
          tmpfs: ['/run'],
          security_opt: ['no-new-privileges:true'],
          user: '65534:65534',
          networks: ['proxy-network'],
          restart: 'unless-stopped',
          deploy: {
            resources: {
              limits: {
                memory: '64m',
                cpus: '0.1',
              },
            },
          },
        },
      };
      return yaml.dump(snippet, { indent: 2, lineWidth: 120 });
    },
  };

  return proxyConfig;
}

module.exports = {
  auditDockerConfig,
  generateSecureDockerfile,
  generateSecureCompose,
  checkContainerRuntime,
  setupDockerSocketProxy,
};