/**
 * Uses the {openssl} utility program's {s_client} and {x509} subcommands 
 * to retrive, parse and verify public SSL/TLS x509 certificates
 * Provides Node.js backend for the CertificateDetails widget
 * @requires openssl
 */
const { exec } = require('child_process');

// string constants used for parsing openssl output
const beginCert = '-----BEGIN CERTIFICATE-----';
const endCert = '-----END CERTIFICATE-----';
const boundary = '\n---\n';
const newLine = '\n';

// error message constants
const E_CONNECT_COMMAND_FAILED = 'Couldn\'t connect to host:port';
const E_CONNECT_NO_RESPONSE = 'Did not receive a response from host:port';
const E_CONNECT_UNEXPECTED_RESPONSE = 'Unexpected response when reading certificates from host:port';
const E_NO_CERTIFICATES = 'host:port did not return any certificates';
const E_PARSE_COMMAND_FAILED = 'Couldn\'t parse certificate :n retreived from host:port';
const E_PARSE_NO_DATES = 'Couldn\'t find validity period dates in certificate :n from host:port';
const E_PARSE_NO_SUBJECT_OR_ISSUER = 'Couldn\'t find subject or issuer in certificate :n from host:port';
const E_INVALID_INPUT = 'Invalid input provided for host:port';
const E_INVALID_INPUT_M = 'Couldn\t parse hosts specification';
const E_UNEXPECTED_ERROR = 'Unexpected error';
const E_CERTIFICATE_VERIFY_FAIL = 'The certificate chain didn\'t pass verification';

// error code message map
const errorCodes = {
  1: { code: 'E_CONNECT_COMMAND_FAILED', message: E_CONNECT_COMMAND_FAILED },
  2: { code: 'E_CONNECT_NO_RESPONSE', message: E_CONNECT_NO_RESPONSE },
  3: { code: 'E_CONNECT_UNEXPECTED_RESPONSE', message: E_CONNECT_UNEXPECTED_RESPONSE },
  4: { code: 'E_NO_CERTIFICATES', message: E_NO_CERTIFICATES },
  5: { code: 'E_PARSE_COMMAND_FAILED', message: E_PARSE_COMMAND_FAILED },
  6: { code: 'E_PARSE_NO_DATES', message: E_PARSE_NO_DATES },
  7: { code: 'E_PARSE_NO_SUBJECT_OR_ISSUER', message: E_PARSE_NO_SUBJECT_OR_ISSUER },
  8: { code: 'E_INVALID_INPUT', message: E_INVALID_INPUT },
  9: { code: 'E_INVALID_INPUT_M', message: E_INVALID_INPUT_M },
  10: { code: 'E_UNEXPECTED_ERROR', message: E_UNEXPECTED_ERROR },
  11: { code: 'E_CERTIFICATE_VERIFY_FAIL', message: E_CERTIFICATE_VERIFY_FAIL },
}

// openssl (1.1.1) verify return codes (https://www.openssl.org/docs/man1.1.1/man1/verify.html)
const opensslCodes = {
  0: 'X509_V_OK',
  1: 'X509_V_ERR_UNSPECIFIED',
  2: 'X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT',
  3: 'X509_V_ERR_UNABLE_TO_GET_CRL',
  4: 'X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE',
  5: 'X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE',
  6: 'X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY',
  7: 'X509_V_ERR_CERT_SIGNATURE_FAILURE',
  8: 'X509_V_ERR_CRL_SIGNATURE_FAILURE',
  9: 'X509_V_ERR_CERT_NOT_YET_VALID',
  10: 'X509_V_ERR_CERT_HAS_EXPIRED',
  11: 'X509_V_ERR_CRL_NOT_YET_VALID',
  12: 'X509_V_ERR_CRL_HAS_EXPIRED',
  13: 'X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD',
  14: 'X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD',
  15: 'X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD',
  16: 'X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD',
  17: 'X509_V_ERR_OUT_OF_MEM',
  18: 'X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT',
  19: 'X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN',
  20: 'X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  21: 'X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  22: 'X509_V_ERR_CERT_CHAIN_TOO_LONG',
  23: 'X509_V_ERR_CERT_REVOKED',
  24: 'X509_V_ERR_INVALID_CA',
  25: 'X509_V_ERR_PATH_LENGTH_EXCEEDED',
  26: 'X509_V_ERR_INVALID_PURPOSE',
  27: 'X509_V_ERR_CERT_UNTRUSTED',
  28: 'X509_V_ERR_CERT_REJECTED',
  29: 'X509_V_ERR_SUBJECT_ISSUER_MISMATCH',
  30: 'X509_V_ERR_AKID_SKID_MISMATCH',
  31: 'X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH',
  32: 'X509_V_ERR_KEYUSAGE_NO_CERTSIGN',
  33: 'X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER',
  34: 'X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION',
  35: 'X509_V_ERR_KEYUSAGE_NO_CRL_SIGN',
  36: 'X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION',
  37: 'X509_V_ERR_INVALID_NON_CA',
  38: 'X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED',
  39: 'X509_V_ERR_PROXY_SUBJECT_INVALID',
  40: 'X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE',
  41: 'X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED',
  42: 'X509_V_ERR_INVALID_EXTENSION',
  43: 'X509_V_ERR_INVALID_POLICY_EXTENSION',
  44: 'X509_V_ERR_NO_EXPLICIT_POLICY',
  45: 'X509_V_ERR_DIFFERENT_CRL_SCOPE',
  46: 'X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE',
  47: 'X509_V_ERR_UNNESTED_RESOURCE',
  48: 'X509_V_ERR_PERMITTED_VIOLATION',
  49: 'X509_V_ERR_EXCLUDED_VIOLATION',
  50: 'X509_V_ERR_SUBTREE_MINMAX',
  51: 'X509_V_ERR_APPLICATION_VERIFICATION',
  52: 'X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE',
  53: 'X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX',
  54: 'X509_V_ERR_UNSUPPORTED_NAME_SYNTAX',
  55: 'X509_V_ERR_CRL_PATH_VALIDATION_ERROR',
  56: 'X509_V_ERR_PATH_LOOP',
  57: 'X509_V_ERR_SUITE_B_INVALID_VERSION',
  58: 'X509_V_ERR_SUITE_B_INVALID_ALGORITHM',
  59: 'X509_V_ERR_SUITE_B_INVALID_CURVE',
  60: 'X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM',
  61: 'X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED',
  62: 'X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256',
  63: 'X509_V_ERR_HOSTNAME_MISMATCH',
  64: 'X509_V_ERR_EMAIL_MISMATCH',
  65: 'X509_V_ERR_IP_ADDRESS_MISMATCH',
  66: 'X509_V_ERR_DANE_NO_MATCH',
  67: 'X509_V_ERR_EE_KEY_TOO_SMALL',
  68: 'X509_ERR_CA_KEY_TOO_SMALL',
  69: 'X509_ERR_CA_MD_TOO_WEAK',
  70: 'X509_V_ERR_INVALID_CALL',
  71: 'X509_V_ERR_STORE_LOOKUP',
  72: 'X509_V_ERR_NO_VALID_SCTS',
  73: 'X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION',
  74: 'X509_V_ERR_OCSP_VERIFY_NEEDED',
  75: 'X509_V_ERR_OCSP_VERIFY_FAILED',
  76: 'X509_V_ERR_OCSP_CERT_UNKNOWN',
};

/**
 * Helper to generate an error object
 * @param {Number} errorCode internal error number
 * @param {Error} nodeError error raised by Node engine when {exec()} terminates
 *                with non-zero return code; OR OpenSSL verify error
 * @param {Number} certificateIndex certficate chain list index
 * @returns {Object} dictionary with error details
 */
const makeError = (host, port, errorCode, nodeError = null, certificateIndex = null) => {
  const code = errorCodes[errorCode].code;
  const message = errorCodes[errorCode].message.replace('host:port', `${host}:${port}`);
  const status = { code: errorCode, text: 'error' };
  const error = { code, message };
  if (certificateIndex) message.replace(':n', certificateIndex);
  if (nodeError && nodeError.message) {
    console.error(nodeError);
    const m = nodeError.message.match(/\.c:\d+:([^\n]+)\n/);
    if (m && m.length > 1) error.reason = m[1];
    const n = nodeError.message.match(/:([^:]+):[a-z0-9/_]+\.c:\d+:\n/);
    if (n && n.length > 1) error.reason = `${n[1]} ${error.reason ?? ''}`;
  } else if (nodeError && nodeError.code) {
    error.reason = nodeError.text;
    error.verify = {code: nodeError.code, message: opensslCodes[nodeError.code] };
    if (nodeError.code === 10) status.text = 'expired';
  }
  return { host, port, error, status };
};

/** 
 * Retrieve and verify the certificate chain for host:port (openssl s_client) 
 * @param {String} host FQDN of host
 * @param {Number} port port on host to connect to
 * @returns {Promise} resolving an array of encoded certificate strings 
 */
const retrieveCertificateChain = (host, port) => {
  return new Promise((resolve, reject) => {
    const cmd = `echo -n | openssl s_client -connect ${host}:${port} -showcerts`;
    exec(cmd, (err, stdout, stderr) => {
      if (err) return reject(makeError(host, port, 1, err));
      if (!stdout) return reject(makeError(host, port, 2));
      // take the certificate (chain) section in output
      const parts = stdout.split(boundary);
      if (parts.length < 2) return reject(makeError(host, port, 3));
      // and slice the encoded certificate strings into an array
      const certs = parts[1].split(`${newLine}${endCert}`);
      const certificates = [];
      certs.forEach(cert => {
        const certParts = cert.split(`${beginCert}${newLine}`);
        if (!certParts[1]) return;
        const certToCheck = [
          `${newLine}${beginCert}${newLine}`, certParts[1], `${newLine}${endCert}${newLine}`
        ].join('');
        certificates.push(certToCheck);
      });
      if (!certificates.length) return reject(makeError(host, port, 4));
      // find chain verify status in output
      const s0 = stdout.match(/Verify return code:\s*(\d+)\s+\(([^\)]+)\)\s*/);
      const text = ((s0.length > 2 && s0[2]) ? s0[2].trim() : 'unknown');
      const code = s0.length > 1 && s0[1] ? parseInt(s0[1]) || 0 : -15;
      const status = { code, text };
      // add error for non-zero openssl verify return code but proceed to parse certs
      let error;
      if (code !== 0) {
        const err = makeError(host, port, 11, { text, code });
        status.code = err.status.code;
        status.text = err.status.text;
        error = err.error;
      }
      // return certifcate status and certificate chain
      resolve({ host, port, status, certificates, error });
    });
  });
};

/** 
 * Parse individual certificate details (openssl x509)
 * @param {String} host FQDN of host (used in error message only)
 * @param {Number} port port on host (used in error message only)
 * @param {String} certificate the encoded certificate string to parse
 * @param {Number} index certificate chain list index id (used in error message only)
 * @returns {Primise} resolving a dictionary of certificate details
 */
const parseCertificate = (host, port, certificate, index) => {
  return new Promise((resolve, reject) => {
    const cmd = `echo "${certificate}" | openssl x509 -noout -text && `
              + `echo "${certificate}" | openssl x509 -noout -fingerprint; `
              + `echo "${certificate}" | openssl x509 -noout -fingerprint -sha256`;
    exec(cmd, (err, stdout, stderr) => {
      if (err) return reject(makeError(host, port, 5, err, index));
      // find validity period start and end dates
      const m1 = stdout.match(/Not Before\s*:\s*(.*)/);
      const m2 = stdout.match(/Not After\s*:\s*(.*)/);
      // generate error if either of start or end dates are not found
      if ((!m1 || m1.length < 2) || (!m2 || m2.length < 2)) {
        return reject(makeError(host, port, 6, null, index));
      }
      const validFrom = m1 && m1.length > 1 ? m1[1] : '';
      const validTo = m2 && m2.length > 1 ? m2[1] : '';
      // calculate days to expiry
      const daysLeft = Math.round(
        (new Date(Date.parse(validTo)) - new Date()) / 24 / 60 / 60 / 1000,
      );
      // find issuer and subject details
      const n1 = stdout.match(/Issuer:\s*.*O\s=\s([^,\n]+)(,\sCN\s=\s([^\n]+))?/);
      const n2 = stdout.match(/Subject:\s*.*?(O\s=\s(.*),\s)?CN\s=\s(.*)/);
      // generate error if neither of issuer and subject are found
      if ((!n1 || n1.length < 3) && (!n2 || n2.length < 4)) {
        return reject(makeError(host, port, 7, null, index));
      }
      let org = n1 ? n1[1] : '';
      let cn = n1 ? n1[3] : '';
      const issuer = { org, cn };
      org = n2 ? n2[2] : '';
      cn = n2 ? n2[3] : '';
      const subject = { org, cn };
      // find fingerprints
      const fingerprints = {};
      const f1 = stdout.match(/SHA1 Fingerprint=([^\s]+)\s+/);
      const f2 = stdout.match(/SHA256 Fingerprint=([^\s]+)(\s|\n)/);
      if (f1 && f1.length > 1) fingerprints.sha1 = f1[1];
      if (f2 && f2.length > 1) fingerprints.sha256 = f2[1];
      // return certificate details
      resolve({ issuer, subject, validFrom, validTo, fingerprints, daysLeft });
    });
  });
};

// ----- // Process single host // ----- //

/**
 * Given a list of encoded certificate strings (the chain retrieved from host), 
 * create a list of promises each resolving parsed certificate details 
 * @param {Array[String]} chain List of encoded certificate strings
 * @returns {Object} dictionary containing the resolved certificates details 
 *          and potentially an error object passed on by {retrieveCertificateChain} 
 */
const processCertificates = async (chain) => {
  const { host, port, status, error } = chain;
  
  const promises = [];
  chain.certificates.forEach((certificate, idx) => {
    promises.push(parseCertificate(host, port, certificate, idx));
  });
  const certificates = await Promise.all(promises);
  status.daysLeft = certificates[0].daysLeft;
  status.lastUpdated = new Date().getTime();

  return { host, port, status, certificates, error };
};

/** 
 * Sanitise host name and port number user input arguments, passed in
 * either as {params} or {host} and {port}
 * @param {URLSearchParams} params containing 'host' and 'port'
 * @param {String} host FQDN of host
 * @param {String} port port number
 * @returns {Object} a dictionary with cleaned 'host' and 'port'
 */
const sanitiseInput = (params = null, host = null, port = null) => {
  const h = params ? params.get('host') : host;
  const p = params ? params.get('port') : port;
  // ensure host is a dot separated list composed of characters allowed in domain names
  const cleanHost = h.toLowerCase().split('.').filter(n => /^[a-z0-9\-]+$/.test(n)).join('.');
  const cleanPort = parseInt(p) || 0; // ensure port is a number

  return { host: cleanHost, port: cleanPort };
};

/**
 * Get all certificates' details for a single host:port
 * @param {String} host the sanitised host name
 * @param {Number} port the sanitised port number
 * @returns {Object} a dictionary with certificate details
 */
const getCertificateDetails = async (host, port) => {
  return retrieveCertificateChain(host, port)
    .then(processCertificates)
    .then(res => {
      const error = res?.error;
      const status = res.status;
      const certificates = res.certificates;
      return { host, port, status, certificates, error };
    });
};

/**
 * Public API method to handle the '/fetch-certificate' endpoint
 * @param {String} paramStr URL-encoded query string input
 * @param {Function} render callback function to execute with results
 */
const fetchCertificate = (paramStr, render) => {
  const params = new URLSearchParams(paramStr);
  const { host, port } = sanitiseInput(params);
  if (!host || !port) return render(JSON.stringify(makeError(host, port, 8)));

  getCertificateDetails(host, port)
    .then(result => render(JSON.stringify(result)))
    .catch(error => render(JSON.stringify(error)));
};

exports.fetchCertificate = fetchCertificate;

// ----- // Process multiple hosts // ----- //

/**
 * Process the query string, parsing each host specification of host:port to host name and port number
 * @param {URLSearchParams} params containing multiple 'hosts' entries in the format of hosts=host:port
 * @returns {Array[Object]} list of dictionaries with sanitised 'host' and 'port'
 */
const parseHosts = (params) => {
  const request = params.getAll('hosts');
  if (!request || !request.length) return [];

  const hosts = [];
  request.forEach(input => {
    const [ h, p ] = input.split(':');
    const { host, port } = sanitiseInput(null, h, p);
    hosts.push({ host, port });
  });
  
  return hosts;
}

/**
 * Public API method to handle the '/fetch-certificates' endpoint
 * @param {String} paramStr URL-encoded query string input
 * @param {Function} render callback function to execute with results
 */
const fetchCertificates = (paramStr, render) => {
  const params = new URLSearchParams(paramStr);
  const hosts = parseHosts(params);
  if (!hosts.length) return render(JSON.stringify(makeError(null, null, 9)))

  const promises = [];
  hosts.forEach(spec => promises.push(getCertificateDetails(spec.host, spec.port)));

  Promise.allSettled(promises)
    .then(result => result.map(entry => entry.value || entry.reason))
    .then(result => render(JSON.stringify(result)))
    .catch(error => render(JSON.stringify(makeError(null, null, 10, error))));
};

exports.fetchCertificates = fetchCertificates;