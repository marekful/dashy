
const { exec } = require('child_process');

const beginCert = '-----BEGIN CERTIFICATE-----';
const endCert = '-----END CERTIFICATE-----';
const boundary = '\n---\n';
const newLine = '\n';

/** Retrieve all certificates for host:port via openssl s_client */
const retrieveCertificates = (host, port) => {
  return new Promise((resolve, reject) => {
    const cmd = `echo -n | openssl s_client -connect ${host}:${port} -showcerts`;
    exec(cmd, (err, stdout, stderr) => {
      if (err) return reject({ code: 1, error: err });
      if (!stdout) return reject({ code: 2 });
      // take the certificates section in output
      const parts = stdout.split(boundary);
      if (parts.length < 2) return reject({ code: 3 });
      // and slice them into an array
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
      if (!certificates.length) return reject({ code: 4 });
      // return certifcates array
      resolve(certificates);
    });
  });
};

/** Parse individual certificate details */
const getCertificateDetails = (certificate) => {
  return new Promise((resolve, reject) => {
    const cmd = `echo "${certificate}" | openssl x509 -text -noout`;
    exec(cmd, (err, stdout, stderr) => {
      if (err) return reject({ code: 5, error: err });
      // find start and end dates
      const m1 = stdout.match(/Not Before\s*:\s*(.*)/);
      const m2 = stdout.match(/Not After\s*:\s*(.*)/);
      if ((!m1 || m1.length < 2) && (!m2 || m2.length < 2)) return reject({ code: 6 });
      const validFrom = m1 && m1.length > 1 ? m1[1] : '';
      const validTo = m2 && m2.length > 1 ? m2[1] : '';
      // find issuer and subject details
      const n1 = stdout.match(/Issuer:\s*.*O\s=\s(.*),\sCN\s=\s(.*)/);
      const n2 = stdout.match(/Subject:\s*.*?(O\s=\s(.*),\s)?CN\s=\s(.*)/);
      if ((!n1 || n1.length < 3) && (!n2 || n2.length < 4)) return reject({ code: 7 });
      const issuer = { org: n1[1], cn: n1[2] };
      const subject = { org: n2[2], cn: n2[3] };
      // return certificate details
      resolve({ issuer, subject, validFrom, validTo });
    });
  });
};

const processCertificates = (certificates) => {
  const promises = [];
  certificates.forEach(certificate => {
    promises.push(getCertificateDetails(certificate));
  });
  return Promise.all(promises);
};

const sanitiseInput = (params) => {
  const h = params.get('host');
  const p = params.get('port');

  const host = h.split('.').map(n => n.toLowerCase())
                .filter(n => /^[a-z0-9\-]+$/.test(n)).join('.');
  const port = parseInt(p) || 0;

  return { host, port };
};

module.exports = (paramStr, render) => {
  const params = new URLSearchParams(paramStr);
  const { host, port } = sanitiseInput(params);

  if (!host || !port) return render(JSON.stringify({code: 8}));

  retrieveCertificates(host, port)
    .then(processCertificates)
    .then(certificates => ({ host, port, certificates }))
    .then(result => render(JSON.stringify(result)))
    .catch((error) => render(JSON.stringify(error)));
};