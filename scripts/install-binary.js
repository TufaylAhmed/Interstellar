'use strict';

/**
 * Download Interstellar release binary into vendor/ for the current platform.
 * Failures are non-fatal when INTERSTELLAR_SKIP_DOWNLOAD=1 or asset is missing
 * (Windows/Linux until those release assets exist).
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');
const { resolvePlatform } = require('./platform');

const ROOT = path.resolve(__dirname, '..');
const VENDOR = path.join(ROOT, 'vendor');
const PKG = require(path.join(ROOT, 'package.json'));
const VERSION = process.env.INTERSTELLAR_VERSION || PKG.version;
const REPO = 'TufaylAhmed/Interstellar';

function log(msg) {
  console.log(`@sequr3/interstellar: ${msg}`);
}

function warn(msg) {
  console.warn(`@sequr3/interstellar: ${msg}`);
}

function get(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'interstellar-npm-install' } }, (res) => {
        if (
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location &&
          redirects < 5
        ) {
          res.resume();
          return resolve(get(res.headers.location, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

function extractTarGz(archivePath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  execFileSync('tar', ['-xzf', archivePath, '-C', destDir], { stdio: 'inherit' });
}

function extractZip(archivePath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === 'win32') {
    execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-Command',
        `Expand-Archive -Path '${archivePath.replace(/'/g, "''")}' -DestinationPath '${destDir.replace(/'/g, "''")}' -Force`,
      ],
      { stdio: 'inherit' }
    );
  } else {
    execFileSync('unzip', ['-o', archivePath, '-d', destDir], { stdio: 'inherit' });
  }
}

async function main() {
  if (process.env.INTERSTELLAR_SKIP_DOWNLOAD === '1') {
    log('skipping binary download (INTERSTELLAR_SKIP_DOWNLOAD=1)');
    return;
  }

  const plat = resolvePlatform();
  if (!plat) {
    warn(
      `unsupported platform ${process.platform}/${process.arch}. Build from source: cargo build --release`
    );
    return;
  }

  const asset = `interstellar-v${VERSION}-${plat.id}.${plat.archiveExt}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
  const vendorBin = path.join(
    VENDOR,
    process.platform === 'win32' ? 'interstellar.exe' : 'interstellar'
  );

  if (fs.existsSync(vendorBin)) {
    log(`binary already present: ${vendorBin}`);
    return;
  }

  fs.mkdirSync(VENDOR, { recursive: true });
  const tmpDir = path.join(VENDOR, '.tmp');
  fs.mkdirSync(tmpDir, { recursive: true });
  const archivePath = path.join(tmpDir, asset);

  log(`downloading ${url}`);
  let buf;
  try {
    buf = await get(url);
  } catch (e) {
    if (plat.optional) {
      warn(
        `no prebuilt binary for ${plat.id} (v${VERSION}). ` +
          `Install Rust and run: cargo install --git https://github.com/${REPO}.git --tag v${VERSION} interstellar-cli`
      );
      warn(String(e.message || e));
      return;
    }
    warn(`download failed: ${e.message || e}`);
    warn('You can build from source with: cargo build --release');
    // Don't fail npm install on darwin if network blips — still exit 0 for optional UX
    // For primary macOS assets, exit non-zero so users notice.
    process.exitCode = 1;
    return;
  }

  fs.writeFileSync(archivePath, buf);

  if (plat.archiveExt === 'tar.gz') {
    extractTarGz(archivePath, tmpDir);
  } else {
    extractZip(archivePath, tmpDir);
  }

  const extracted = path.join(tmpDir, plat.binaryName);
  if (!fs.existsSync(extracted)) {
    // search recursively
    const found = walkFind(tmpDir, plat.binaryName);
    if (!found) {
      warn(`extracted archive missing ${plat.binaryName}`);
      process.exitCode = 1;
      return;
    }
    fs.copyFileSync(found, vendorBin);
  } else {
    fs.copyFileSync(extracted, vendorBin);
  }

  if (process.platform !== 'win32') {
    fs.chmodSync(vendorBin, 0o755);
  }

  // cleanup tmp
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (_) {
    /* ignore */
  }

  log(`installed ${vendorBin}`);
}

function walkFind(dir, name) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const ent of entries) {
    const p = path.join(dir, ent.name);
    if (ent.isFile() && ent.name === name) return p;
    if (ent.isDirectory()) {
      const hit = walkFind(p, name);
      if (hit) return hit;
    }
  }
  return null;
}

main().catch((e) => {
  warn(e.stack || String(e));
  process.exitCode = 1;
});
