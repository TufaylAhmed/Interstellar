#!/usr/bin/env node
'use strict';

/**
 * npm bin launcher for Interstellar.
 * Prefers vendor/ binary installed by postinstall; falls back to PATH.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const vendorBin = path.join(
  ROOT,
  'vendor',
  process.platform === 'win32' ? 'interstellar.exe' : 'interstellar'
);

function which(cmd) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  const r = spawnSync(finder, [cmd], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
    windowsHide: true,
  });
  if (r.status !== 0) return null;
  return String(r.stdout || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .find(Boolean);
}

function resolveBinary() {
  if (fs.existsSync(vendorBin)) return vendorBin;
  const envBin = process.env.INTERSTELLAR_BIN;
  if (envBin && fs.existsSync(envBin)) return envBin;
  const onPath = which('interstellar');
  if (onPath && path.resolve(onPath) !== path.resolve(__filename)) {
    // avoid recursion if PATH points at this shim
    if (!onPath.endsWith('interstellar.js')) return onPath;
  }
  return null;
}

const bin = resolveBinary();
if (!bin) {
  console.error(`interstellar: native binary not found.

Tried: ${vendorBin}

Fix:
  1) Re-run: npm explore @sequr3/interstellar -- npm run install-binary
  2) Or download a release: https://github.com/TufaylAhmed/Interstellar/releases
  3) Or build: cargo build --release  (then set INTERSTELLAR_BIN)

Platform: ${process.platform}/${process.arch}
`);
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), {
  stdio: 'inherit',
  windowsHide: true,
});

if (result.error) {
  console.error(`interstellar: failed to spawn ${bin}: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status == null ? 1 : result.status);
