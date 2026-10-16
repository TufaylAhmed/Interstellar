'use strict';

/**
 * Map Node platform/arch → GitHub release asset stem.
 * Assets: interstellar-vX.Y.Z-<platform>.tar.gz (or .zip on Windows later)
 */
function resolvePlatform() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'darwin' && arch === 'arm64') {
    return {
      id: 'macos-aarch64',
      binaryName: 'interstellar-macos-aarch64',
      archiveExt: 'tar.gz',
    };
  }
  if (platform === 'darwin' && (arch === 'x64' || arch === 'ia32')) {
    return {
      id: 'macos-x86_64',
      binaryName: 'interstellar-macos-x86_64',
      archiveExt: 'tar.gz',
    };
  }
  if (platform === 'linux' && arch === 'x64') {
    return {
      id: 'linux-x86_64',
      binaryName: 'interstellar-linux-x86_64',
      archiveExt: 'tar.gz',
      optional: true,
    };
  }
  if (platform === 'linux' && arch === 'arm64') {
    return {
      id: 'linux-aarch64',
      binaryName: 'interstellar-linux-aarch64',
      archiveExt: 'tar.gz',
      optional: true,
    };
  }
  if (platform === 'win32' && (arch === 'x64' || arch === 'arm64')) {
    return {
      id: arch === 'arm64' ? 'windows-arm64' : 'windows-x86_64',
      binaryName:
        arch === 'arm64'
          ? 'interstellar-windows-arm64.exe'
          : 'interstellar-windows-x86_64.exe',
      archiveExt: 'zip',
      optional: true,
    };
  }

  return null;
}

module.exports = { resolvePlatform };
