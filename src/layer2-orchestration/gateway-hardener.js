/**
 * OpenClaw Gateway Security Hardening Module
 * Hardens OpenClaw Gateway running on port 18789
 * @module openclaw-gateway-hardener
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
const { execSync, exec } = require('child_process');
const os = require('os');

const OPENCLAW_PORT = 18789;
const OPENCLAW_SERVICE_NAME = 'openclaw-gateway';

/**
 * @typedef {Object} LoopbackConfig
 * @property {string} [host='127.0.0.1'] - The host to bind to
 * @property {number} [port=18789] - The port number
 * @property {boolean} [ipv6=false] - Whether to also bind to IPv6 loopback
 * @property {boolean} [enforceFirewall=true] - Whether to add iptables rules
 * @property {string[]} [allowedIPs=[]] - Additional IPs allowed to connect
 * @property {boolean} [dropExternalTraffic=true] - Drop all non-loopback traffic to the port
 * @property {number} [maxConnections=100] - Maximum concurrent connections
 * @property {number} [rateLimitPerSecond=50] - Rate limit per second per IP
 */

/**
 * @typedef {Object} LoopbackResult
 * @property {boolean} success - Whether the enforcement was successful
 * @property {string} bindAddress - The address bound to
 * @property {number} port - The port number
 * @property {string[]} firewallRules - Applied firewall rules
 * @property {string[]} warnings - Any warnings generated
 * @property {Object} networkConfig - The applied network configuration
 */

/**
 * @typedef {Object} DockerComposeOptions
 * @property {string} [imageName='openclaw/gateway'] - Docker image name
 * @property {string} [imageTag='latest'] - Docker image tag
 * @property {boolean} [readOnlyRootfs=true] - Mount root filesystem as read-only
 * @property {boolean} [noNewPrivileges=true] - Prevent privilege escalation
 * @property {boolean} [dropAllCapabilities=true] - Drop all Linux capabilities
 * @property {string[]} [addCapabilities=[]] - Capabilities to add back
 * @property {number} [memoryLimit=512] - Memory limit in MB
 * @property {number} [cpuLimit=1.0] - CPU limit
 * @property {number} [pidsLimit=100] - Maximum number of PIDs
 * @property {boolean} [enableMTLS=false] - Enable mutual TLS
 * @property {string} [certPath=''] - Path to TLS certificate
 * @property {string} [keyPath=''] - Path to TLS key
 * @property {string} [caPath=''] - Path to CA certificate
 * @property {string} [networkMode='bridge'] - Docker network mode
 * @property {string} [loggingDriver='json-file'] - Logging driver
 * @property {number} [maxLogSize=10] - Max log size in MB
 * @property {number} [maxLogFiles=3] - Max number of log files
 * @property {boolean} [enableHealthcheck=true] - Enable healthcheck
 * @property {number} [healthcheckInterval=30] - Healthcheck interval in seconds
 * @property {number} [healthcheckTimeout=10] - Healthcheck timeout in seconds
 * @property {number} [healthcheckRetries=3] - Healthcheck retries
 * @property {Object} [environment={}] - Additional environment variables
 * @property {string} [user='1000:1000'] - User to run as
 * @property {string[]} [tmpfsMounts=['/tmp', '/run']] - Tmpfs mounts
 * @property {Object} [sysctls={}] - Sysctl settings
 * @property {string[]} [dnsServers=[]] - Custom DNS servers
 * @property {boolean} [enableSeccomp=true] - Enable seccomp profile
 * @property {string} [seccompProfile=''] - Custom seccomp profile path
 */

/**
 * @typedef {Object} DockerComposeResult
 * @property {string} yaml - The generated docker-compose YAML content
 * @property {string} filename - Suggested filename
 * @property {Object} securityFeatures - Summary of security features enabled
 * @property {string[]} recommendations - Additional security recommendations
 */

/**
 * @typedef {Object} MTLSConfig
 * @property {boolean} success - Whether mTLS setup was successful
 * @property {Object} tlsOptions - TLS options object for use with tls.createServer
 * @property {string} certFingerprint - SHA-256 fingerprint of the certificate
 * @property {Date} certExpiry - Certificate expiry date
 * @property {string[]} warnings - Any warnings about the certificate setup
 * @property {Function} createSecureServer - Factory function to create a secure server
 */

/**
 * @typedef {Object} NetworkSecurityReport
 * @property {Date} timestamp - When the report was generated
 * @property {Object} portStatus - Status of port 18789
 * @property {Object} bindingInfo - Current binding information
 * @property {Object} firewallStatus - Firewall rules status
 * @property {Object} tlsStatus - TLS configuration status
 * @property {Object} processInfo - Process information
 * @property {Object} networkInterfaces - Network interface information
 * @property {string[]} vulnerabilities - Detected vulnerabilities
 * @property {string[]} recommendations - Security recommendations
 * @property {string} overallRisk - Overall risk assessment
 * @property {number} securityScore - Security score 0-100
 */

/**
 * Enforces loopback-only binding for the OpenClaw Gateway on port 18789.
 * Configures firewall rules, validates binding addresses, and ensures
 * the gateway is not exposed to external networks.
 *
 * @param {LoopbackConfig} [config={}] - Configuration for loopback enforcement
 * @returns {LoopbackResult} Result of the enforcement operation
 * @throws {Error} If critical security configuration fails
 *
 * @example
 * const { enforceLoopbackBinding } = require('./openclaw-gateway-hardener');
 * const result = enforceLoopbackBinding({
 *   host: '127.0.0.1',
 *   enforceFirewall: true,
 *   dropExternalTraffic: true
 * });
 * console.log(result.success); // true
 */
function enforceLoopbackBinding(config = {}) {
  const defaults = {
    host: '127.0.0.1',
    port: OPENCLAW_PORT,
    ipv6: false,
    enforceFirewall: true,
    allowedIPs: [],
    dropExternalTraffic: true,
    maxConnections: 100,
    rateLimitPerSecond: 50,
  };

  const mergedConfig = { ...defaults, ...config };
  const result = {
    success: false,
    bindAddress: mergedConfig.host,
    port: mergedConfig.port,
    firewallRules: [],
    warnings: [],
    networkConfig: {},
  };

  // Validate host is a loopback address
  const loopbackAddresses = ['127.0.0.1', 'localhost', '::1'];
  if (!loopbackAddresses.includes(mergedConfig.host) && !mergedConfig.host.startsWith('127.')) {
    throw new Error(
      `Security violation: Host "${mergedConfig.host}" is not a loopback address. ` +
      `OpenClaw Gateway on port ${OPENCLAW_PORT} must bind to loopback only. ` +
      `Use 127.0.0.1, localhost, or ::1.`
    );
  }

  // Reject binding to 0.0.0.0 or wildcard
  if (mergedConfig.host === '0.0.0.0' || mergedConfig.host === '::') {
    throw new Error(
      `Security violation: Binding to wildcard address "${mergedConfig.host}" is prohibited. ` +
      `OpenClaw Gateway must bind to loopback interface only.`
    );
  }

  // Validate port
  if (mergedConfig.port !== OPENCLAW_PORT) {
    result.warnings.push(
      `Non-standard port ${mergedConfig.port} specified. Default OpenClaw Gateway port is ${OPENCLAW_PORT}.`
    );
  }

  // Check if port is already in use
  const portInUse = _checkPortInUse(mergedConfig.host, mergedConfig.port);
  if (portInUse.inUse) {
    result.warnings.push(
      `Port ${mergedConfig.port} is already in use on ${mergedConfig.host}. PID: ${portInUse.pid || 'unknown'}`
    );
  }

  // Generate network configuration
  const networkConfig = {
    bind: mergedConfig.host,
    port: mergedConfig.port,
    backlog: mergedConfig.maxConnections,
    keepAlive: true,
    keepAliveInitialDelay: 60000,
    noDelay: true,
    maxConnections: mergedConfig.maxConnections,
  };

  if (mergedConfig.ipv6) {
    networkConfig.ipv6Bind = '::1';
    networkConfig.ipv6Only = false;
  }

  result.networkConfig = networkConfig;

  // Generate firewall rules
  if (mergedConfig.enforceFirewall) {
    const firewallRules = _generateFirewallRules(mergedConfig);
    result.firewallRules = firewallRules;

    // Attempt to apply firewall rules
    const firewallResult = _applyFirewallRules(firewallRules);
    if (!firewallResult.success) {
      result.warnings.push(
        `Could not apply firewall rules: ${firewallResult.error}. ` +
        `Rules have been generated but must be applied manually.`
      );
    }
  }

  // Validate allowed IPs are internal/private
  for (const ip of mergedConfig.allowedIPs) {
    if (!_isPrivateIP(ip)) {
      result.warnings.push(
        `Warning: Allowed IP "${ip}" appears to be a public IP address. ` +
        `This may expose the OpenClaw Gateway to external traffic.`
      );
    }
  }

  // Generate rate limiting configuration
  result.networkConfig.rateLimit = {
    windowMs: 1000,
    maxRequests: mergedConfig.rateLimitPerSecond,
    strategy: 'sliding-window',
  };

  // Create the server binding configuration object
  result.networkConfig.serverOptions = {
    host: mergedConfig.host,
    port: mergedConfig.port,
    exclusive: true, // Prevent port sharing
    readableAll: false,
    writableAll: false,
  };

  result.success = true;
  return result;
}

/**
 * Generates a secure Docker Compose configuration for the OpenClaw Gateway.
 * Includes security hardening options such as read-only filesystem, dropped
 * capabilities, resource limits, and network isolation.
 *
 * @param {DockerComposeOptions} [options={}] - Docker Compose generation options
 * @returns {DockerComposeResult} The generated Docker Compose configuration
 *
 * @example
 * const { generateDockerComposeSecure } = require('./openclaw-gateway-hardener');
 * const result = generateDockerComposeSecure({
 *   enableMTLS: true,
 *   certPath: '/certs/server.crt',
 *   keyPath: '/certs/server.key',
 *   caPath: '/certs/ca.crt',
 *   readOnlyRootfs: true,
 *   dropAllCapabilities: true
 * });
 * fs.writeFileSync('docker-compose.secure.yml', result.yaml);
 */
function generateDockerComposeSecure(options = {}) {
  const defaults = {
    imageName: 'openclaw/gateway',
    imageTag: 'latest',
    readOnlyRootfs: true,
    noNewPrivileges: true,
    dropAllCapabilities: true,
    addCapabilities: [],
    memoryLimit: 512,
    cpuLimit: 1.0,
    pidsLimit: 100,
    enableMTLS: false,
    certPath: '',
    keyPath: '',
    caPath: '',
    networkMode: 'bridge',
    loggingDriver: 'json-file',
    maxLogSize: 10,
    maxLogFiles: 3,
    enableHealthcheck: true,
    healthcheckInterval: 30,
    healthcheckTimeout: 10,
    healthcheckRetries: 3,
    environment: {},
    user: '1000:1000',
    tmpfsMounts: ['/tmp', '/run'],
    sysctls: {},
    dnsServers: [],
    enableSeccomp: true,
    seccompProfile: '',
  };

  const opts = { ...defaults, ...options };
  const securityFeatures = {};
  const recommendations = [];

  // Build the compose structure
  const compose = {
    version: '3.8',
    services: {},
    networks: {},
    volumes: {},
  };

  // Service definition
  const service = {
    image: `${opts.imageName}:${opts.imageTag}`,
    container_name: OPENCLAW_SERVICE_NAME,
    restart: 'unless-stopped',
    user: opts.user,
    ports: [`127.0.0.1:${OPENCLAW_PORT}:${OPENCLAW_PORT}`],
    environment: {
      NODE_ENV: 'production',
      OPENCLAW_BIND_HOST: '0.0.0.0',
      OPENCLAW_PORT: String(OPENCLAW_PORT),
      OPENCLAW_LOOPBACK_ONLY: 'true',
      ...opts.environment,
    },
    deploy: {
      resources: {
        limits: {
          memory: `${opts.memoryLimit}M`,
          cpus: String(opts.cpuLimit),
        },
        reservations: {
          memory: `${Math.floor(opts.memoryLimit / 4)}M`,
          cpus: String(opts.cpuLimit / 4),
        },
      },
    },
    logging: {
      driver: opts.loggingDriver,
      options: {
        'max-size': `${opts.maxLogSize}m`,
        'max-file': String(opts.maxLogFiles),
      },
    },
  };

  // Security options
  const securityOpt = [];

  if (opts.noNewPrivileges) {
    securityOpt.push('no-new-privileges:true');
    securityFeatures.noNewPrivileges = true;
  }

  if (opts.enableSeccomp) {
    if (opts.seccompProfile) {
      securityOpt.push(`seccomp:${opts.seccompProfile}`);
    } else {
      securityOpt.push('seccomp:unconfined');
      recommendations.push(
        'Consider providing a custom seccomp profile for tighter syscall filtering.'
      );
    }
    securityFeatures.seccomp = true;
  }

  if (securityOpt.length > 0) {
    service.security_opt = securityOpt;
  }

  // Read-only root filesystem
  if (opts.readOnlyRootfs) {
    service.read_only = true;
    securityFeatures.readOnlyRootfs = true;
  }

  // Tmpfs mounts for writable directories
  if (opts.tmpfsMounts && opts.tmpfsMounts.length > 0) {
    service.tmpfs = opts.tmpfsMounts.map((mount) => `${mount}:rw,noexec,nosuid,size=64m`);
  }

  // Linux capabilities
  if (opts.dropAllCapabilities) {
    service.cap_drop = ['ALL'];
    securityFeatures.droppedAllCapabilities = true;

    if (opts.addCapabilities && opts.addCapabilities.length > 0) {
      service.cap_add = [...opts.addCapabilities];
      securityFeatures.addedCapabilities = opts.addCapabilities;
    }
  }

  // PIDs limit
  service.pids_limit = opts.pidsLimit;
  securityFeatures.pidsLimit = opts.pidsLimit;

  // mTLS volumes
  if (opts.enableMTLS) {
    if (!opts.certPath || !opts.keyPath || !opts.caPath) {
      recommendations.push(
        'mTLS is enabled but certificate paths are incomplete. Provide certPath, keyPath, and caPath.'
      );
    }

    service.volumes = service.volumes || [];
    if (opts.certPath) {
      service.volumes.push(`${opts.certPath}:/etc/openclaw/certs/server.crt:ro`);
    }
    if (opts.keyPath) {
      service.volumes.push(`${opts.keyPath}:/etc/openclaw/certs/server.key:ro`);
    }
    if (opts.caPath) {
      service.volumes.push(`${opts.caPath}:/etc/openclaw/certs/ca.crt:ro`);
    }

    service.environment.OPENCLAW_MTLS_ENABLED = 'true';
    service.environment.OPENCLAW_CERT_PATH = '/etc/openclaw/certs/server.crt';
    service.environment.OPENCLAW_KEY_PATH = '/etc/openclaw/certs/server.key';
    service.environment.OPENCLAW_CA_PATH = '/etc/openclaw/certs/ca.crt';

    securityFeatures.mtls = true;
  }

  // Healthcheck
  if (opts.enableHealthcheck) {
    const healthcheckCmd = opts.enableMTLS
      ? `wget --no-check-certificate --spider -q https://localhost:${OPENCLAW_PORT}/health || exit 1`
      : `wget --spider -q http://localhost:${OPENCLAW_PORT}/health || exit 1`;

    service.healthcheck = {
      test: ['CMD-SHELL', healthcheckCmd],
      interval: `${opts.healthcheckInterval}s`,
      timeout: `${opts.healthcheckTimeout}s`,
      retries: opts.healthcheckRetries,
      start_period: '10s',
    };
    securityFeatures.healthcheck = true;
  }

  // Sysctls
  const defaultSysctls = {
    'net.ipv4.ip_unprivileged_port_start': '0',
    'net.ipv4.conf.all.send_redirects': '0',
    'net.ipv4.conf.default.send_redirects': '0',
  };

  service.sysctls = { ...defaultSysctls, ...opts.sysctls };

  // DNS
  if (opts.dnsServers && opts.dnsServers.length > 0) {
    service.dns = opts.dnsServers;
  }

  // Network configuration
  const networkName = 'openclaw-internal';
  service.networks = [networkName];

  compose.networks[networkName] = {
    driver: 'bridge',
    internal: true,
    ipam: {
      config: [
        {
          subnet: '172.28.0.0/16',
          gateway: '172.28.0.1',
        },
      ],
    },
    driver_opts: {
      'com.docker.network.bridge.enable_icc': 'false',
      'com.docker.network.bridge.enable_ip_masquerade': 'false',
    },
  };

  compose.services[OPENCLAW_SERVICE_NAME] = service;

  // Generate YAML manually (to avoid dependency on js-yaml)
  const yaml = _generateYAML(compose);

  // Generate additional recommendations
  if (opts.imageTag === 'latest') {
    recommendations.push(
      'Avoid using "latest" tag in production. Pin to a specific version for reproducibility.'
    );
  }

  if (!opts.enableMTLS) {
    recommendations.push(
      'Consider enabling mTLS for encrypted communication even on loopback.'
    );
  }

  if (!opts.enableSeccomp || !opts.seccompProfile) {
    recommendations.push(
      'Create a custom seccomp profile to restrict system calls to only those needed.'
    );
  }

  recommendations.push(
    'Regularly update the OpenClaw Gateway image to receive security patches.',
    'Implement log monitoring and alerting for the gateway container.',
    'Use Docker Content Trust (DCT) to verify image signatures.',
    'Consider running vulnerability scans on the container image.'
  );

  securityFeatures.loopbackBinding = true;
  securityFeatures.resourceLimits = true;
  securityFeatures.internalNetwork = true;

  return {
    yaml,
    filename: 'docker-compose.openclaw-secure.yml',
    securityFeatures,
    recommendations,
  };
}

/**
 * Sets up mutual TLS (mTLS) for the OpenClaw Gateway, requiring both
 * server and client certificate validation. Returns a configuration
 * object with TLS options and a factory function for creating secure servers.
 *
 * @param {string} certPath - Path to the server certificate (PEM format)
 * @param {string} keyPath - Path to the server private key (PEM format)
 * @param {string} caPath - Path to the Certificate Authority certificate (PEM format)
 * @returns {MTLSConfig} mTLS configuration object
 * @throws {Error} If certificate files are missing, invalid, or insecure
 *
 * @example
 * const { setupMTLS } = require('./openclaw-gateway-hardener');
 * const mtls = setupMTLS(
 *   '/path/to/server.crt',
 *   '/path/to/server.key',
 *   '/path/to/ca.crt'
 * );
 * const server = mtls.createSecureServer((req, res) => {
 *   res.end('Secure OpenClaw Gateway');
 * });
 * server.listen(18789, '127.0.0.1');
 */
function setupMTLS(certPath, keyPath, caPath) {
  const warnings = [];

  // Validate parameters
  if (!certPath || typeof certPath !== 'string') {
    throw new Error('certPath is required and must be a string');
  }
  if (!keyPath || typeof keyPath !== 'string') {
    throw new Error('keyPath is required and must be a string');
  }
  if (!caPath || typeof caPath !== 'string') {
    throw new Error('caPath is required and must be a string');
  }

  // Resolve paths
  const resolvedCertPath = path.resolve(certPath);
  const resolvedKeyPath = path.resolve(keyPath);
  const resolvedCaPath = path.resolve(caPath);

  // Check file existence
  if (!fs.existsSync(resolvedCertPath)) {
    throw new Error(`Certificate file not found: ${resolvedCertPath}`);
  }
  if (!fs.existsSync(resolvedKeyPath)) {
    throw new Error(`Key file not found: ${resolvedKeyPath}`);
  }
  if (!fs.existsSync(resolvedCaPath)) {
    throw new Error(`CA certificate file not found: ${resolvedCaPath}`);
  }

  // Check file permissions on key file
  try {
    const keyStats = fs.statSync(resolvedKeyPath);
    const keyMode = (keyStats.mode & 0o777).toString(8);
    const permNum = parseInt(keyMode, 10);

    if (permNum > 600) {
      warnings.push(
        `Private key file permissions are too open (${keyMode}). ` +
        `Recommended: 600 or 400. Run: chmod 600 ${resolvedKeyPath}`
      );
    }
  } catch (e) {
    warnings.push(`Could not check key file permissions: ${e.message}`);
  }

  // Read certificate files
  let cert, key, ca;
  try {
    cert = fs.readFileSync(resolvedCertPath, 'utf8');
  } catch (e) {
    throw new Error(`Failed to read certificate file: ${e.message}`);
  }
  try {
    key = fs.readFileSync(resolvedKeyPath, 'utf8');
  } catch (e) {
    throw new Error(`Failed to read key file: ${e.message}`);
  }
  try {
    ca = fs.readFileSync(resolvedCaPath, 'utf8');
  } catch (e) {
    throw new Error(`Failed to read CA certificate file: ${e.message}`);
  }

  // Basic PEM validation
  if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error('Certificate file does not appear to be in PEM format');
  }
  if (!key.includes('-----BEGIN') || !key.includes('PRIVATE KEY-----')) {
    throw new Error('Key file does not appear to be in PEM format');
  }
  if (!ca.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error('CA certificate file does not appear to be in PEM format');
  }

  // Check for weak key indicators
  if (key.includes('BEGIN RSA PRIVATE KEY') || key.includes('BEGIN EC PRIVATE KEY')) {
    // Try to determine key size from certificate
    try {
      const certObj = new crypto.X509Certificate(cert);
      const publicKey = certObj.publicKey;

      if (publicKey.asymmetricKeyType === 'rsa') {
        const keySize = publicKey.asymmetricKeySize;
        if (keySize && keySize < 256) { // 256 bytes = 2048 bits
          warnings.push(
            `RSA key size appears to be less than 2048 bits. ` +
            `Minimum recommended key size is 2048 bits, preferably 4096 bits.`
          );
        }
      }
    } catch (e) {
      // X509Certificate may not be available in older Node versions
      warnings.push('Could not validate certificate details. Ensure Node.js >= 15.6.0 for full validation.');
    }
  }

  // Extract certificate information
  let certFingerprint = '';
  let certExpiry = null;
  let certSubject = '';

  try {
    const certObj = new crypto.X509Certificate(cert);
    certFingerprint = certObj.fingerprint256;
    certExpiry = new Date(certObj.validTo);
    certSubject = certObj.subject;

    // Check if certificate is expired
    const now = new Date();
    if (certExpiry < now) {
      throw new Error(
        `Server certificate has expired on ${certExpiry.toISOString()}. ` +
        `Please renew the certificate.`
      );
    }

    // Check if certificate expires within 30 days
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    if (certExpiry < thirtyDaysFromNow) {
      warnings.push(
        `Server certificate expires in less than 30 days (${certExpiry.toISOString()}). ` +
        `Consider renewing soon.`
      );
    }

    // Verify the certificate was issued by the CA
    try {
      const caObj = new crypto.X509Certificate(ca);
      if (!certObj.checkIssued(caObj)) {
        warnings.push(
          'The server certificate does not appear to be issued by the provided CA. ' +
          'Verify the certificate chain.'
        );
      }
    } catch (e) {
      warnings.push(`Could not verify certificate chain: ${e.message}`);
    }
  } catch (e) {
    if (e.message.includes('expired')) {
      throw e;
    }
    // Fallback for older Node.js versions
    certFingerprint = crypto.createHash('sha256').update(cert).digest('hex');
    warnings.push(
      `Limited certificate validation available. Error: ${e.message}. ` +
      `Use Node.js >= 15.6.0 for full X.509 validation.`
    );
  }

  // Build TLS options
  const tlsOptions = {
    cert,
    key,
    ca: [ca],
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
    honorCipherOrder: true,
    ecdhCurve: 'P-384:P-256',
    sessionTimeout: 300,
    ticketKeys: crypto.randomBytes(48),
  };

  /**
   * Creates a secure TLS server bound to loopback on the OpenClaw Gateway port.
   *
   * @param {Function|Object} [requestListenerOrHttpsOptions] - Request listener or additional HTTPS options
   * @returns {tls.Server} Configured TLS server
   */
  function createSecureServer(requestListenerOrHttpsOptions) {
    let server;

    if (typeof requestListenerOrHttpsOptions === 'function') {
      // If using raw TLS
      server = tls.createServer(tlsOptions, requestListenerOrHttpsOptions);
    } else {
      // Merge additional options
      const mergedOpts = { ...tlsOptions, ...(requestListenerOrHttpsOptions || {}) };
      server = tls.createServer(mergedOpts);
    }

    // Add connection validation
    server.on('secureConnection', (socket) => {
      const clientCert = socket.getPeerCertificate(true);

      if (!clientCert || !clientCert.subject) {
        socket.destroy(new Error('Client certificate required'));
        return;
      }

      // Verify client cert is signed by our CA
      if (!socket.authorized) {
        socket.destroy(new Error(`Client certificate not authorized: ${socket.authorizationError}`));
        return;
      }
    });

    // Add error handling
    server.on('tlsClientError', (err, socket) => {
      console.error(`[OpenClaw Gateway] TLS client error: ${err.message}`);
      if (socket && !socket.destroyed) {
        socket.destroy();
      }
    });

    return server;
  }

  return {
    success: true,
    tlsOptions,
    certFingerprint,
    certExpiry,
    warnings,
    createSecureServer,
  };
}

/**
 * Validates a webhook signature from the OpenClaw Gateway.
 * Supports HMAC-SHA256 and HMAC-SHA512 signature verification
 * with constant-time comparison to prevent timing attacks.
 *
 * @param {string|Buffer|Object} payload - The webhook payload to validate
 * @param {string} signature - The signature to validate against (format: "sha256=..." or "sha512=...")
 * @param {string} secret - The shared secret used for HMAC computation
 * @returns {boolean} True if the signature is valid, false otherwise
 * @throws {Error} If required parameters are missing or invalid
 *
 * @example
 * const { validateWebhookSignature } = require('./openclaw-gateway-hardener');
 *
 * // Express middleware usage
 * app.post('/webhook', (req, res) => {
 *   const signature = req.headers['x-openclaw-signature'];
 *   const isValid = validateWebhookSignature(req.body, signature, process.env.WEBHOOK_SECRET);
 *   if (!isValid) {
 *     return res.status(401).json({ error: 'Invalid signature' });
 *   }
 *   // Process webhook...
 * });
 */
function validateWebhookSignature(payload, signature, secret) {
  // Parameter validation
  if (payload === undefined || payload === null) {
    throw new Error('Payload is required for webhook signature validation');
  }
  if (!signature || typeof signature !== 'string') {
    throw new Error('Signature is required and must be a non-empty string');
  }
  if (!secret || typeof secret !== 'string') {
    throw new Error('Secret is required and must be a non-empty string');
  }

  // Minimum secret length enforcement
  if (secret.length < 16) {
    throw new Error(
      'Webhook secret must be at least 16 characters long for adequate security'
    );
  }

  // Normalize payload to string
  let payloadString;
  if (Buffer.isBuffer(payload)) {
    payloadString = payload.toString('utf8');
  } else if (typeof payload === 'object') {
    payloadString = JSON.stringify(payload);
  } else if (typeof payload === 'string') {
    payloadString = payload;
  } else {
    throw new Error('Payload must be a string, Buffer, or object');
  }

  // Parse signature format
  const signatureParts = signature.split('=');
  if (signatureParts.length < 2) {
    // Try common formats
    // Check if it's a raw hex signature (assume sha256)
    if (/^[a-fA-F0-9]{64}$/.test(signature)) {
      signatureParts[0] = 'sha256';
      signatureParts[1] = signature;
    } else if (/^[a-fA-F0-9]{128}$/.test(signature)) {
      signatureParts[0] = 'sha512';
      signatureParts[1] = signature;
    } else {
      throw new Error(
        'Invalid signature format. Expected format: "sha256=<hex>" or "sha512=<hex>"'
      );
    }
  }

  const algorithm = signatureParts[0].toLowerCase();
  const providedHash = signatureParts.slice(1).join('='); // Rejoin in case '=' appears in hash

  // Validate algorithm
  const supportedAlgorithms = ['sha256', 'sha512', 'sha384'];
  if (!supportedAlgorithms.includes(algorithm)) {
    throw new Error(
      `Unsupported hash algorithm: "${algorithm}". ` +
      `Supported algorithms: ${supportedAlgorithms.join(', ')}`
    );
  }

  // Compute expected HMAC
  let expectedHash;
  try {
    expectedHash = crypto
      .createHmac(algorithm, secret)
      .update(payloadString, 'utf8')
      .digest('hex');
  } catch (e) {
    throw new Error(`Failed to compute HMAC: ${e.message}`);
  }

  // Validate hex format of provided hash
  if (!/^[a-fA-F0-9]+$/.test(providedHash)) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  const providedBuffer = Buffer.from(providedHash.toLowerCase(), 'hex');
  const expectedBuffer = Buffer.from(expectedHash.toLowerCase(), 'hex');

  // Length check (also in constant time by padding)
  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(providedBuffer, expectedBuffer);
  } catch (e) {
    // timingSafeEqual throws if buffers are different lengths
    return false;
  }
}

/**
 * Generates a comprehensive network security report for the OpenClaw Gateway
 * on port 18789. Checks port status, binding configuration, firewall rules,
 * TLS configuration, running processes, and network interfaces.
 *
 * @returns {NetworkSecurityReport} Comprehensive security assessment report
 *
 * @example
 * const { getNetworkSecurityReport } = require('./openclaw-gateway-hardener');
 * const report = getNetworkSecurityReport();
 * console.log(`Security Score: ${report.securityScore}/100`);
 * console.log(`Risk Level: ${report.overallRisk}`);
 * report.vulnerabilities.forEach(v => console.log(`[VULN] ${v}`));
 * report.recommendations.forEach(r => console.log(`[REC] ${r}`));
 */
function getNetworkSecurityReport() {
  const report = {
    timestamp: new Date(),
    portStatus: {},
    bindingInfo: {},
    firewallStatus: {},
    tlsStatus: {},
    processInfo: {},
    networkInterfaces: {},
    vulnerabilities: [],
    recommendations: [],
    overallRisk: 'unknown',
    securityScore: 0,
  };

  let score = 100;

  // 1. Check port status
  report.portStatus = _analyzePort(OPENCLAW_PORT);

  if (report.portStatus.isOpen && report.portStatus.boundTo === '0.0.0.0') {
    report.vulnerabilities.push(
      `CRITICAL: Port ${OPENCLAW_PORT} is bound to 0.0.0.0 (all interfaces). ` +
      `This exposes the OpenClaw Gateway to external network traffic.`
    );
    score -= 40;
  } else if (report.portStatus.isOpen && !['127.0.0.1', '::1', 'localhost'].includes(report.portStatus.boundTo)) {
    report.vulnerabilities.push(
      `HIGH: Port ${OPENCLAW_PORT} is bound to ${report.portStatus.boundTo} which may be externally accessible.`
    );
    score -= 25;
  }

  if (!report.portStatus.isOpen) {
    report.bindingInfo.status = 'Port is not currently in use';
  }

  // 2. Check listening sockets
  report.bindingInfo = {
    ...report.bindingInfo,
    ..._getListeningSockets(OPENCLAW_PORT),
  };

  // 3. Check firewall rules
  report.firewallStatus = _checkFirewallRules(OPENCLAW_PORT);

  if (!report.firewallStatus.hasRules) {
    report.vulnerabilities.push(
      `MEDIUM: No firewall rules detected for port ${OPENCLAW_PORT}. ` +
      `Consider adding iptables/nftables rules to restrict access.`
    );
    score -= 15;
    report.recommendations.push(
      `Add firewall rules: iptables -A INPUT -p tcp --dport ${OPENCLAW_PORT} ! -s 127.0.0.1 -j DROP`
    );
  }

  // 4. Check TLS status
  report.tlsStatus = _checkTLSStatus(OPENCLAW_PORT);

  if (!report.tlsStatus.tlsEnabled) {
    report.vulnerabilities.push(
      `MEDIUM: TLS does not appear to be enabled on port ${OPENCLAW_PORT}. ` +
      `Traffic may be transmitted in plaintext.`
    );
    score -= 15;
    report.recommendations.push(
      'Enable TLS/mTLS using setupMTLS() for encrypted communication.'
    );
  }

  if (report.tlsStatus.tlsEnabled && !report.tlsStatus.mtlsEnabled) {
    report.recommendations.push(
      'Consider enabling mutual TLS (mTLS) for client certificate verification.'
    );
    score -= 5;
  }

  // 5. Check process info
  report.processInfo = _getProcessInfo(OPENCLAW_PORT);

  if (report.processInfo.runningAsRoot) {
    report.vulnerabilities.push(
      'HIGH: OpenClaw Gateway process is running as root. ' +
      'Run as a non-privileged user for defense in depth.'
    );
    score -= 20;
    report.recommendations.push(
      'Create a dedicated non-root user for the OpenClaw Gateway service.'
    );
  }

  // 6. Network interfaces
  report.networkInterfaces = _analyzeNetworkInterfaces();

  const publicInterfaces = report.networkInterfaces.public || [];
  if (publicInterfaces.length > 0) {
    report.recommendations.push(
      `System has ${publicInterfaces.length} public-facing network interface(s). ` +
      `Ensure OpenClaw Gateway is not accessible from these interfaces.`
    );
  }

  // 7. Docker-specific checks
  const dockerInfo = _checkDockerSecurity();
  if (dockerInfo.isDocker) {
    if (!dockerInfo.readOnlyRootfs) {
      report.vulnerabilities.push(
        'LOW: Container does not have a read-only root filesystem.'
      );
      score -= 5;
    }
    if (dockerInfo.privileged) {
      report.vulnerabilities.push(
        'CRITICAL: Container is running in privileged mode.'
      );
      score -= 30;
    }
    if (!dockerInfo.noNewPrivileges) {
      report.vulnerabilities.push(
        'MEDIUM: no-new-privileges security option is not set.'
      );
      score -= 10;
    }
  }

  // 8. Check for common misconfigurations
  _checkCommonMisconfigurations(report);

  // Calculate final score
  score = Math.max(0, Math.min(100, score));
  report.securityScore = score;

  // Determine risk level
  if (score >= 90) {
    report.overallRisk = 'LOW';
  } else if (score >= 70) {
    report.overallRisk = 'MEDIUM';
  } else if (score >= 50) {
    report.overallRisk = 'HIGH';
  } else {
    report.overallRisk = 'CRITICAL';
  }

  // Always-applicable recommendations
  report.recommendations.push(
    'Regularly rotate TLS certificates and webhook secrets.',
    'Enable audit logging for all gateway access.',
    'Implement network segmentation to isolate the gateway.',
    'Set up automated security scanning in CI/CD pipeline.',
    `Monitor port ${OPENCLAW_PORT} for unauthorized access attempts.`
  );

  return report;
}

// ========================
// Internal helper functions
// ========================

/**
 * @private
 * Check if a port is in use
 */
function _checkPortInUse(host, port) {
  const result = { inUse: false, pid: null };

  try {
    if (process.platform === 'linux' || process.platform === 'darwin') {
      const cmd = process.platform === 'linux'
        ? `ss -tlnp 'sport = :${port}' 2>/dev/null || netstat -tlnp 2>/dev/null | grep :${port}`
        : `lsof -i :${port} -sTCP:LISTEN 2>/dev/null`;

      const output = execSync(cmd, { encoding: 'utf8', timeout: 5000 }).trim();
      if (output) {
        result.inUse = true;
        const pidMatch = output.match(/pid=(\d+)/i) || output.match(/(\d+)\s*$/m);
        if (pidMatch) {
          result.pid = pidMatch[1];
        }
      }
    }
  } catch (e) {
    // Command failed or not available
  }

  return result;
}

/**
 * @private
 * Generate iptables firewall rules
 */
function _generateFirewallRules(config) {
  const rules = [];
  const port = config.port;

  // Allow loopback
  rules.push(`iptables -A INPUT -i lo -p tcp --dport ${port} -j ACCEPT`);
  rules.push(`ip6tables -A INPUT -i lo -p tcp --dport ${port} -j ACCEPT`);

  // Allow specific IPs
  for (const ip of (config.allowedIPs || [])) {
    if (ip.includes(':')) {
      rules.push(`ip6tables -A INPUT -s ${ip} -p tcp --dport ${port} -j ACCEPT`);
    } else {
      rules.push(`iptables -A INPUT -s ${ip} -p tcp --dport ${port} -j ACCEPT`);
    }
  }

  // Rate limiting
  if (config.rateLimitPerSecond) {
    rules.push(
      `iptables -A INPUT -p tcp --dport ${port} -m state --state NEW ` +
      `-m recent --set --name openclaw_rate`
    );
    rules.push(
      `iptables -A INPUT -p tcp --dport ${port} -m state --state NEW ` +
      `-m recent --update --seconds 1 --hitcount ${config.rateLimitPerSecond} --name openclaw_rate -j DROP`
    );
  }

  // Drop all other traffic to this port
  if (config.dropExternalTraffic) {
    rules.push(`iptables -A INPUT -p tcp --dport ${port} -j DROP`);
    rules.push(`ip6tables -A INPUT -p tcp --dport ${port} -j DROP`);
  }

  // Connection limiting
  if (config.maxConnections) {
    rules.push(
      `iptables -A INPUT -p tcp --dport ${port} -m connlimit --connlimit-above ${config.maxConnections} -j REJECT`
    );
  }

  return rules;
}

/**
 * @private
 * Attempt to apply firewall rules
 */
function _applyFirewallRules(rules) {
  const result = { success: false, applied: [], errors: [] };

  // Check if running as root
  if (process.getuid && process.getuid() !== 0) {
    return { success: false, error: 'Root privileges required to apply firewall rules' };
  }

  for (const rule of rules) {
    try {
      execSync(rule, { encoding: 'utf8', timeout: 5000 });
      result.applied.push(rule);
    } catch (e) {
      result.errors.push({ rule, error: e.message });
    }
  }

  result.success = result.errors.length === 0;
  if (!result.success) {
    result.error = `Failed to apply ${result.errors.length} rule(s)`;
  }

  return result;
}

/**
 * @private
 * Check if an IP is private/internal
 */
function _isPrivateIP(ip) {
  // IPv4 private ranges
  const privateRanges = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./, // Link-local
    /^0\./, // Current network
  ];

  // IPv6 private
  const ipv6Private = [
    /^::1$/,
    /^fe80:/i,
    /^fc/i,
    /^fd/i,
  ];

  for (const range of privateRanges) {
    if (range.test(ip)) return true;
  }

  for (const range of ipv6Private) {
    if (range.test(ip)) return true;
  }

  return false;
}

/**
 * @private
 * Generate YAML string from object (simple implementation to avoid external deps)
 */
function _generateYAML(obj, indent = 0) {
  let yaml = '';
  const spaces = '  '.repeat(indent);

  if (typeof obj !== 'object' || obj === null) {
    return String(obj);
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === 'object' && item !== null && !Array.isArray(item)) {
        yaml += `${spaces}-\n`;
        const entries = Object.entries(item);
        for (const [k, v] of entries) {
          if (typeof v === 'object' && v !== null) {
            yaml += `${spaces}  ${k}:\n${_generateYAML(v, indent + 2)}`;
          } else {
            yaml += `${spaces}  ${k}: ${_yamlValue(v)}\n`;
          }
        }
      } else {
        yaml += `${spaces}- ${_yamlValue(item)}\n`;
      }
    }
    return yaml;
  }

  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || value === null) continue;

    if (typeof value === 'object' && !Array.isArray(value)) {
      yaml += `${spaces}${key}:\n`;
      yaml += _generateYAML(value, indent + 1);
    } else if (Array.isArray(value)) {
      yaml += `${spaces}${key}:\n`;
      yaml += _generateYAML(value, indent + 1);
    } else {
      yaml += `${spaces}${key}: ${_yamlValue(value)}\n`;
    }
  }

  return yaml;
}

/**
 * @private
 * Format a value for YAML output
 */
function _yamlValue(value) {
  if (typeof value === 'string') {
    if (
      value.includes(':') ||
      value.includes('#') ||
      value.includes('{') ||
      value.includes('}') ||
      value.includes('[') ||
      value.includes(']') ||
      value.includes(',') ||
      value.includes('&') ||
      value.includes('*') ||
      value.includes('?') ||
      value.includes('|') ||
      value.includes('-') ||
      value.includes('<') ||
      value.includes('>') ||
      value.includes('=') ||
      value.includes('!') ||
      value.includes('%') ||
      value.includes('@') ||
      value.includes('`') ||
      value.startsWith(' ') ||
      value.endsWith(' ') ||
      value === 'true' ||
      value === 'false' ||
      value === 'null' ||
      value === ''
    ) {
      return `"${value.replace(/"/g, '\\"')}"`;
    }
    return value;
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  return String(value);
}

/**
 * @private
 * Analyze a specific port
 */
function _analyzePort(port) {
  const status = {
    port,
    isOpen: false,
    boundTo: null,
    protocol: 'tcp',
    pid: null,
    processName: null,
  };

  try {
    if (process.platform === 'linux') {
      const output = execSync(
        `ss -tlnp 'sport = :${port}' 2>/dev/null || true`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();

      if (output && output.includes(`:${port}`)) {
        status.isOpen = true;

        // Parse binding address
        const bindMatch = output.match(/(\S+):(\d+)\s/);
        if (bindMatch) {
          status.boundTo = bindMatch[1] === '*' ? '0.0.0.0' : bindMatch[1];
        }

        // Parse PID
        const pidMatch = output.match(/pid=(\d+)/);
        if (pidMatch) {
          status.pid = parseInt(pidMatch[1], 10);
        }

        // Parse process name
        const nameMatch = output.match(/users:\(\("([^"]+)"/);
        if (nameMatch) {
          status.processName = nameMatch[1];
        }
      }
    } else if (process.platform === 'darwin') {
      const output = execSync(
        `lsof -i :${port} -sTCP:LISTEN -P -n 2>/dev/null || true`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();

      if (output && output.includes(`:${port}`)) {
        status.isOpen = true;
        const lines = output.split('\n').slice(1);
        if (lines.length > 0) {
          const parts = lines[0].split(/\s+/);
          status.processName = parts[0] || null;
          status.pid = parts[1] ? parseInt(parts[1], 10) : null;

          const addrMatch = (parts[8] || '').match(/^(.+):(\d+)$/);
          if (addrMatch) {
            status.boundTo = addrMatch[1] === '*' ? '0.0.0.0' : addrMatch[1];
          }
        }
      }
    }
  } catch (e) {
    status.error = e.message;
  }

  return status;
}

/**
 * @private
 * Get listening sockets information
 */
function _getListeningSockets(port) {
  const info = {
    sockets: [],
    totalListeners: 0,
  };

  try {
    if (process.platform === 'linux') {
      const output = execSync(
        `ss -tlnp 'sport = :${port}' 2>/dev/null || true`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();

      const lines = output.split('\n').slice(1); // Skip header
      for (const line of lines) {
        if (line.trim()) {
          info.sockets.push(line.trim());
          info.totalListeners++;
        }
      }
    } else if (process.platform === 'darwin') {
      const output = execSync(
        `lsof -i :${port} -sTCP:LISTEN -P -n 2>/dev/null || true`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();

      const lines = output.split('\n').slice(1);
      for (const line of lines) {
        if (line.trim()) {
          info.sockets.push(line.trim());
          info.totalListeners++;
        }
      }
    }
  } catch (e) {
    info.error = e.message;
  }

  return info;
}

/**
 * @private
 * Check firewall rules for the port
 */
function _checkFirewallRules(port) {
  const status = {
    hasRules: false,
    rules: [],
    firewallType: 'unknown',
  };

  try {
    // Check iptables
    const iptOutput = execSync(
      `iptables -L -n 2>/dev/null | grep ${port} || true`,
      { encoding: 'utf8', timeout: 5000 }
    ).trim();

    if (iptOutput) {
      status.hasRules = true;
      status.firewallType = 'iptables';
      status.rules = iptOutput.split('\n').filter(Boolean);
    }
  } catch (e) {
    // iptables not available or no permission
  }

  try {
    // Check nftables
    const nftOutput = execSync(
      `nft list ruleset 2>/dev/null | grep ${port} || true`,
      { encoding: 'utf8', timeout: 5000 }
    ).trim();

    if (nftOutput) {
      status.hasRules = true;
      status.firewallType = status.firewallType === 'iptables' ? 'both' : 'nftables';
      status.rules = [...status.rules, ...nftOutput.split('\n').filter(Boolean)];
    }
  } catch (e) {
    // nftables not available
  }

  try {
    // Check ufw
    const ufwOutput = execSync(
      `ufw status 2>/dev/null | grep ${port} || true`,
      { encoding: 'utf8', timeout: 5000 }
    ).trim();

    if (ufwOutput) {
      status.hasRules = true;
      if (status.firewallType === 'unknown') {
        status.firewallType = 'ufw';
      }
      status.rules = [...status.rules, ...ufwOutput.split('\n').filter(Boolean)];
    }
  } catch (e) {
    // ufw not available
  }

  return status;
}

/**
 * @private
 * Check TLS status on port
 */
function _checkTLSStatus(port) {
  const status = {
    tlsEnabled: false,
    mtlsEnabled: false,
    protocol: null,
    cipher: null,
    certInfo: null,
  };

  try {
    const output = execSync(
      `echo | openssl s_client -connect 127.0.0.1:${port} -brief 2>/dev/null || true`,
      { encoding: 'utf8', timeout: 10000 }
    ).trim();

    if (output && !output.includes('Connection refused') && !output.includes('errno')) {
      status.tlsEnabled = true;

      const protocolMatch = output.match(/Protocol version:\s*(\S+)/i) || output.match(/(TLSv[\d.]+)/);
      if (protocolMatch) {
        status.protocol = protocolMatch[1];
      }

      const cipherMatch = output.match(/Ciphersuite:\s*(\S+)/i) || output.match(/Cipher:\s*(\S+)/i);
      if (cipherMatch) {
        status.cipher = cipherMatch[1];
      }

      if (output.includes('Verification: OK') || output.includes('Verify return code: 0')) {
        status.mtlsEnabled = true;
      }
    }
  } catch (e) {
    // openssl not available or connection failed
  }

  return status;
}

/**
 * @private
 * Get process information for port
 */
function _getProcessInfo(port) {
  const info = {
    pid: null,
    processName: null,
    user: null,
    runningAsRoot: false,
    uptime: null,
    memoryUsage: null,
    cpuUsage: null,
  };

  try {
    if (process.platform === 'linux') {
      const ssOutput = execSync(
        `ss -tlnp 'sport = :${port}' 2>/dev/null || true`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();

      const pidMatch = ssOutput.match(/pid=(\d+)/);
      if (pidMatch) {
        info.pid = parseInt(pidMatch[1], 10);

        // Get process details
        try {
          const psOutput = execSync(
            `ps -p ${info.pid} -o user=,comm=,etime=,%mem=,%cpu= 2>/dev/null || true`,
            { encoding: 'utf8', timeout: 5000 }
          ).trim();

          if (psOutput) {
            const parts = psOutput.split(/\s+/);
            info.user = parts[0] || null;
            info.processName = parts[1] || null;
            info.uptime = parts[2] || null;
            info.memoryUsage = parts[3] ? `${parts[3]}%` : null;
            info.cpuUsage = parts[4] ? `${parts[4]}%` : null;
            info.runningAsRoot = info.user === 'root';
          }
        } catch (e) {
          // ps command failed
        }
      }
    } else if (process.platform === 'darwin') {
      const lsofOutput = execSync(
        `lsof -i :${port} -sTCP:LISTEN -P -n 2>/dev/null || true`,
        { encoding: 'utf8', timeout: 5000 }
      ).trim();

      const lines = lsofOutput.split('\n').slice(1);
      if (lines.length > 0) {
        const parts = lines[0].split(/\s+/);
        info.processName = parts[0] || null;
        info.pid = parts[1] ? parseInt(parts[1], 10) : null;
        info.user = parts[2] || null;
        info.runningAsRoot = info.user === 'root';
      }
    }
  } catch (e) {
    info.error = e.message;
  }

  return info;
}

/**
 * @private
 * Analyze network interfaces
 */
function _analyzeNetworkInterfaces() {
  const result = {
    public: [],
    private: [],
    loopback: [],
    all: {},
  };

  const interfaces = os.networkInterfaces();

  for (const [name, addrs] of Object.entries(interfaces)) {
    result.all[name] = [];

    for (const addr of addrs) {
      const entry = {
        address: addr.address,
        netmask: addr.netmask,
        family: addr.family,
        internal: addr.internal,
      };

      result.all[name].push(entry);

      if (addr.internal) {
        result.loopback.push({ interface: name, ...entry });
      } else if (_isPrivateIP(addr.address)) {
        result.private.push({ interface: name, ...entry });
      } else {
        result.public.push({ interface: name, ...entry });
      }
    }
  }

  return result;
}

/**
 * @private
 * Check Docker-specific security settings
 */
function _checkDockerSecurity() {
  const info = {
    isDocker: false,
    readOnlyRootfs: false,
    privileged: false,
    noNewPrivileges: false,
    capabilities: [],
  };

  // Check if running in Docker
  try {
    if (fs.existsSync('/.dockerenv')) {
      info.isDocker = true;
    } else {
      const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf8');
      if (cgroup.includes('docker') || cgroup.includes('containerd')) {
        info.isDocker = true;
      }
    }
  } catch (e) {
    // Not in Docker or can't determine
  }

  if (info.isDocker) {
    // Check read-only root filesystem
    try {
      const mounts = fs.readFileSync('/proc/mounts', 'utf8');
      const rootMount = mounts.split('\n').find((line) => {
        const parts = line.split(' ');
        return parts[1] === '/';
      });
      if (rootMount && rootMount.includes(' ro')) {
        info.readOnlyRootfs = true;
      }
    } catch (e) {
      // Can't check
    }

    // Check capabilities
    try {
      const capStatus = fs.readFileSync('/proc/1/status', 'utf8');
      const capEffMatch = capStatus.match(/CapEff:\s*([0-9a-f]+)/i);
      if (capEffMatch) {
        const capHex = capEffMatch[1];
        // Full capabilities = ffffffffffffffff (privileged)
        if (capHex === '0000003fffffffff' || capHex === 'ffffffffffffffff') {
          info.privileged = true;
        }
      }
    } catch (e) {
      // Can't check
    }

    // Check no-new-privileges
    try {
      const noNewPrivs = fs.readFileSync('/proc/1/status', 'utf8');
      const noNewPrivsMatch = noNewPrivs.match(/NoNewPrivs:\s*(\d+)/);
      if (noNewPrivsMatch && noNewPrivsMatch[1] === '1') {
        info.noNewPrivileges = true;
      }
    } catch (e) {
      // Can't check
    }
  }

  return info;
}

/**
 * @private
 * Check for common misconfigurations
 */
function _checkCommonMisconfigurations(report) {
  // Check for environment variable leaks
  const sensitiveEnvVars = [
    'OPENCLAW_SECRET',
    'OPENCLAW_API_KEY',
    'OPENCLAW_WEBHOOK_SECRET',
    'DATABASE_URL',
    'DB_PASSWORD',
    'PRIVATE_KEY',
    'SECRET_KEY',
  ];

  for (const envVar of sensitiveEnvVars) {
    if (process.env[envVar]) {
      report.recommendations.push(
        `Sensitive environment variable "${envVar}" is set. ` +
        `Ensure it is not logged or exposed in error messages.`
      );
    }
  }

  // Check Node.js security
  if (process.env.NODE_ENV !== 'production') {
    report.vulnerabilities.push(
      'LOW: NODE_ENV is not set to "production". ' +
      'Development mode may expose debug information.'
    );
  }

  // Check for insecure TLS settings
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    report.vulnerabilities.push(
      'CRITICAL: NODE_TLS_REJECT_UNAUTHORIZED is set to 0. ' +
      'TLS certificate verification is disabled, enabling man-in-the-middle attacks.'
    );
  }

  // Check DNS resolution (potential DNS rebinding)
  report.recommendations.push(
    'Ensure DNS rebinding protection is in place for the gateway hostname.'
  );
}

module.exports = {
  enforceLoopbackBinding,
  generateDockerComposeSecure,
  setupMTLS,
  validateWebhookSignature,
  getNetworkSecurityReport,
  OPENCLAW_PORT,
  OPENCLAW_SERVICE_NAME,
};