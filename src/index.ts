const { promisify } = require('util');
import _cmdExists = require('command-exists');
const commandExists = promisify(_cmdExists);
import installAuthority from './install-authority';
import { generateOpensslConf, generateRootCertificate, generateSignedCertificate, tmpClear } from './openssl';
import fs = require('./fs-promisified');

async function generateDevCert (commonName: string) {
  if (!(await commandExists('openssl')))
    throw new Error('Unable to find openssl - make sure it is installed and available in your PATH');
  if (!commonName.match(/^(.|\.){1,64}$/))
    throw new Error(`Invalid Common Name ${commonName}.`);
  try {
    const opensslConfPath = await generateOpensslConf(commonName);
    const { rootKeyPath, rootCertPath } = await generateRootCertificate(commonName, opensslConfPath);
    await installAuthority(commonName, rootCertPath);
    const { keyPath, certPath, caPath } = await generateSignedCertificate(commonName, opensslConfPath, rootKeyPath, rootCertPath);
    const [key, cert, ca] = await Promise.all([keyPath, certPath, caPath].map(filepath => fs.readFile(filepath, 'utf8')));
    return { key, cert, ca };
  }
  finally {
    // clear all tmp files (including root cert!)
    await tmpClear();
  }
}

export default generateDevCert;
