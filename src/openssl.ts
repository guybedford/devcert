import childProcess = require('child_process');
import path = require('path');
import os = require('os');
import rimraf = require('rimraf');
import fs = require('fs');
import mkdirp = require('mkdirp');

// simple temp file pathing, requires manual removal
let tmpPrefix, tmpFiles;
export function tmpFile (name: string) {
  if (!tmpPrefix) {
    tmpPrefix = path.join(os.tmpdir(), Math.round(Math.random() * 36 ** 10).toString(36));
    tmpFiles = [];
  }
  const tmpFile = tmpPrefix + name;
  let tmpFileUnique = tmpFile;
  let uniqueIndex = 0;
  while (tmpFiles.indexOf(tmpFileUnique) !== -1)
    tmpFileUnique = tmpFile + (++uniqueIndex);
  tmpFiles.push(tmpFileUnique);
  return tmpFileUnique;
}

export function tmpClear () {
  if (tmpFiles) {
    for (let tmpFile of tmpFiles) {
      try {
        fs.unlinkSync(tmpFile);
      }
      catch (_e) {}
    }
  }
}

let rndFile;
function openssl (cmd: string) {
  if (!rndFile)
    rndFile = tmpFile('rnd');
  childProcess.execSync(`openssl ${ cmd }`, {
    stdio: 'ignore',
    env: Object.assign({
      RANDFILE: rndFile
    }, process.env)
  });
}

interface OpensslTemplateOpts {
  commonName: string,
  databasePath: string,
  serialPath: string
};

const newline = /\r\n|\r|\n/g;
const linebreak = process.platform === 'win32' ? '\r\n' : '\n';
function normalizeLinebreaks (str) {
  return str.replace(newline, linebreak);
}

const opensslConfTemplate = ({ commonName, databasePath, serialPath }: OpensslTemplateOpts) => `[ ca ]
# \`man ca\`
default_ca = CA_default

[ CA_default ]
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
policy            = policy_loose
database          = ${databasePath.replace(/\\/g, '\\\\')}
serial            = ${serialPath.replace(/\\/g, '\\\\')}
prompt            = no

[ policy_loose ]
# Only require minimal information for development certificates
commonName              = supplied

[ req ]
# Options for the \`req\` tool (\`man req\`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
commonName                      = Common Name

[ v3_ca ]
# Extensions for a typical CA (\`man x509v3_config\`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
# Extensions for server certificates (\`man x509v3_config\`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "${commonName} Issued Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${commonName}
DNS.2 = localhost
DNS.3 = localhost.localdomain
DNS.4 = lvh.me
DNS.5 = *.lvh.me
DNS.6 = [::1]
IP.1 = 127.0.0.1
IP.2 = fe80::1
`;

export function generateOpensslConf (commonName: string) {
  const opensslConfPath = tmpFile('openssl.conf');
  const databasePath = tmpFile('index.txt');
  const serialPath = tmpFile('serial');
  const opensslConf = opensslConfTemplate({ commonName, databasePath, serialPath });
  fs.writeFileSync(opensslConfPath, normalizeLinebreaks(opensslConf));
  fs.writeFileSync(databasePath, '');
  fs.writeFileSync(serialPath, Math.round(Math.random() * 16 ** 10).toString(16));
  return opensslConfPath;
}

export function generateKey (): string {
  const keyFile = tmpFile('key');
  openssl(`genrsa -out ${keyFile} 2048`);
  fs.chmodSync(keyFile, 400);
  return keyFile;
}

export function generateRootCertificate (commonName: string, opensslConfPath: string) {
  const rootCertPath = tmpFile(`${commonName}.crt`);
  const rootKeyPath = generateKey();
  openssl(`req -config ${opensslConfPath} -key ${rootKeyPath} -out ${rootCertPath} -new -subj "/CN=${commonName}" -x509 -days 825 -extensions v3_ca`);
  return { rootKeyPath, rootCertPath };
}

export function generateSignedCertificate (commonName: string, opensslConfPath: string, rootKeyPath: string, caPath: string) {
  const keyPath = generateKey();
  process.env.SAN = commonName;
  const csrFile = tmpFile(`${commonName}.csr`);
  openssl(`req -config ${ opensslConfPath } -subj "/CN=${commonName}" -key ${keyPath} -out ${csrFile} -new`);
  const certPath = tmpFile(`${commonName}.crt`);
  
  // needed but not used (see https://www.mail-archive.com/openssl-users@openssl.org/msg81098.html)
  const caCertsDir = path.join(os.tmpdir(), Math.round(Math.random() * 36 ** 10).toString(36));
  mkdirp.sync(caCertsDir);

  openssl(`ca -config ${opensslConfPath} -in ${csrFile} -out ${certPath} -outdir ${caCertsDir} -keyfile ${rootKeyPath} -cert ${caPath} -notext -md sha256 -days 825 -batch -extensions server_cert`)

  rimraf.sync(caCertsDir);

  return { keyPath, certPath, caPath };
}
