import { readFileSync, existsSync } from 'fs';
import { exec, execSync } from 'child_process';
import http = require('http');
import path = require('path');
import getPort = require('get-port');
import commandExists = require('command-exists');
import glob = require('glob');

export function waitForUser () {
  return new Promise((resolve) => {
    function waitHandler () {
      resolve();
      process.stdin.removeListener('data', waitHandler);
    }
    process.stdin.resume();
    process.stdin.on('data', waitHandler);
  });
}

// Install the once-per-machine trusted root CA. We'll use this CA to sign per-app certs, allowing
// us to minimize the need for elevated permissions while still allowing for per-app certificates.
export default function installCertificateAuthority (commonName: string, rootCertPath: string): Promise<void> {
  switch (process.platform) {
    case 'darwin':
      return addToMacTrustStores(commonName, rootCertPath);
    case 'linux':
      return addToLinuxTrustStores(commonName, rootCertPath);
    case 'win32':
      return addToWindowsTrustStores(rootCertPath);
    default:
      throw new Error(`Unable to automatically add a root certificate for ${process.platform} platform.`);
  }   
}

// macOS is pretty simple - just add the certificate to the system keychain, and most applications
// will delegate to that for determining trusted certificates. Firefox, of course, does it's own
// thing. We can try to automatically install the cert with Firefox if we can use certutil via the
// `nss` Homebrew package, otherwise we go manual with user-facing prompts.
async function addToMacTrustStores (commonName: string, rootCertPath: string): Promise<void> {
  // Chrome, Safari, system utils
  execSync(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain -p ssl -p basic "${rootCertPath}"`);
  // Firefox
  try {
    // Try to use certutil to install the cert automatically
    await addCertificateToNSSCertDB(commonName, rootCertPath, path.join(process.env.HOME, 'Library/Application Support/Firefox/Profiles/*'), true);
  }
  catch (e) {
    // Otherwise, open the cert in Firefox to install it
    await openCertificateInFirefox(rootCertPath, '/Applications/Firefox.app/Contents/MacOS/firefox');
  }
}

// Linux is surprisingly difficult. There seems to be multiple system-wide repositories for certs,
// so we copy ours to each. However, Firefox does it's usual separate trust store. Plus Chrome
// relies on the NSS tooling (like Firefox), but uses the user's NSS database, unlike Firefox which
// uses a separate Mozilla one. And since Chrome doesn't prompt the user with a GUI flow when
// opening certs, if we can't use certutil, we're out of luck.
async function addToLinuxTrustStores (commonName: string, rootCertPath: string): Promise<void> {
  // system utils
  execSync(`sudo cp ${rootCertPath} /etc/ssl/certs/${commonName}.pem}`);
  execSync(`sudo cp ${rootCertPath} /usr/local/share/ca-certificates/${commonName}.crt`);
  execSync(`sudo update-ca-certificates`);
  // Firefox
  try {
    // Try to use certutil to install the cert automatically
    await addCertificateToNSSCertDB(commonName, rootCertPath, path.join(process.env.HOME, '.mozilla/firefox/*'), true);
  }
  catch (e) {
    // Otherwise, open the cert in Firefox to install it
    await openCertificateInFirefox(rootCertPath, 'firefox');
  }
  // Chrome
  await addCertificateToNSSCertDB(commonName, rootCertPath, path.join(process.env.HOME, '.pki/nssdb'), false);
}

// Windows is at least simple. Like macOS, most applications will delegate to the system trust
// store, which is updated with the confusingly named `certutil` exe (not the same as the
// NSS/Mozilla certutil). Firefox does it's own thing as usual, and getting a copy of NSS certutil
// onto the Windows machine to try updating the Firefox store is basically a nightmare, so we don't
// even try it - we just bail out to the GUI.
async function addToWindowsTrustStores (rootCertPath: string): Promise<void> {
  // IE, Chrome, system utils
  try {
    execSync(`certutil -addstore -user root ${rootCertPath}`);
  }
  catch (e) {}
  // Firefox (don't even try NSS certutil, no easy install for Windows)
  await openCertificateInFirefox(rootCertPath, 'start firefox');
}

// Given a directory or glob pattern of directories, attempt to install the certificate to each
// directory containing an NSS database.
async function addCertificateToNSSCertDB (commonName: string, rootCertPath: string, nssDirGlob: string, checkForOpenFirefox: boolean): Promise<void> {
  let certutilPath = lookupOrInstallCertutil();
  if (!certutilPath)
    throw new Error('certutil not available');
  
  // Firefox appears to load the NSS database in-memory on startup, and overwrite on exit. So we
  // have to ask the user to quite Firefox first so our changes don't get overwritten.
  if (checkForOpenFirefox) {
    let runningProcesses = execSync('ps aux');
    if (runningProcesses.indexOf('firefox') > -1) {
      console.log('Please close Firefox\nPress <Enter> when ready');
      await waitForUser();
    }
  }

  glob.sync(nssDirGlob).forEach(potentialNSSDBDir => {
    if (existsSync(path.join(potentialNSSDBDir, 'cert8.db')))
      execSync(`${certutilPath} -A -d "${potentialNSSDBDir}" -t 'C,,' -i ${rootCertPath} -n ${commonName}`);
    else if (existsSync(path.join(potentialNSSDBDir, 'cert9.db')))
      execSync(`${certutilPath} -A -d "sql:${potentialNSSDBDir}" -t 'C,,' -i ${rootCertPath} -n ${commonName}`);
  });
}

// When a Firefox tab is directed to a URL that returns a certificate, it will automatically prompt
// the user if they want to add it to their trusted certificates. This is handy since Firefox is by
// far the most troublesome to handle. If we can't automatically install the certificate (because
// certutil is not available / installable), we instead start a quick web server and host our
// certificate file. Then we open the hosted cert URL in Firefox to kick off the GUI flow.
async function openCertificateInFirefox(rootCertPath: string, firefoxPath: string): Promise<void> {
  const port = await getPort();
  http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-type': 'application/x-x509-ca-cert' });
    res.write(readFileSync(rootCertPath));
    res.end();
  }).listen(port);
  console.log(`If using Firefox, a Firefox window will be opened for authorization.\nTick the "Trust this CA to identify websites" option and then confirm.\nPress <Enter> to continue.`);
  await waitForUser();
  exec(`${firefoxPath} http://localhost:${port}`);
  console.log(`Press <Enter> once confirmed (or to skip)`);
  await waitForUser();
}

// Try to install certutil if it's not already available, and return the path to the executable
function lookupOrInstallCertutil (): string | void {
  if (process.platform === 'darwin') {
    if (commandExists.sync('brew')) {
      let certutilPath: string;
      try {
        certutilPath = path.join(execSync('brew --prefix nss').toString().trim(), 'bin', 'certutil');
      } catch (e) {
        execSync('brew install nss');
        certutilPath = path.join(execSync('brew --prefix nss').toString().trim(), 'bin', 'certutil');
      }
      return certutilPath;
    }
  }
  else if (process.platform === 'linux') {
    if (!commandExists.sync('certutil'))
      execSync('sudo apt install libnss3-tools');
    return execSync('which certutil').toString().trim();
  }
}
