#!/usr/bin/env node
/**
 * Cubo Fraud Engine — signed release builder.
 *
 * Workflow for shipping a new version (run from desktop/):
 *
 *   1. Bump `version` in src-tauri/tauri.conf.json (and optionally package.json)
 *   2. `npm run release`
 *   3. Follow the printed instructions to create a GitHub release and upload
 *      the three produced files.
 *
 * Behind the scenes, this script:
 *   - Resolves the Tauri signing key from the user's profile (~/.tauri/) or
 *     from $TAURI_SIGNING_PRIVATE_KEY_PATH if set explicitly
 *   - Runs `npm run tauri build` with the signing env vars set, producing
 *     `bundle/nsis/Cubo Fraud Engine_<v>_x64-setup.exe` and a `.sig` next to it
 *   - Generates `bundle/nsis/latest.json` — the manifest the auto-updater
 *     plugin reads from the GitHub Releases endpoint
 *
 * Why a separate script (vs raw `npm run tauri build`):
 *   - Ensures the right env vars are set every time (easy to forget manually
 *     and the build then silently produces an unsigned bundle the updater
 *     can't verify)
 *   - Generates `latest.json` automatically rather than hand-editing JSON
 *   - Prints the exact GitHub upload steps so the release flow is repeatable
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __dirname  = dirname(fileURLToPath(import.meta.url));
const desktopRoot = join(__dirname, '..');

// ──────────────────────────────────────────────────────────────────────────
// 1. Read version + product name from tauri.conf.json (single source of truth).
// ──────────────────────────────────────────────────────────────────────────
const confPath = join(desktopRoot, 'src-tauri', 'tauri.conf.json');
const conf = JSON.parse(readFileSync(confPath, 'utf8'));
const { version, productName } = conf;
if (!version || !productName) {
  console.error('[release] tauri.conf.json is missing version or productName.');
  process.exit(1);
}
console.log(`\n[release] Building ${productName} v${version}\n`);

// ──────────────────────────────────────────────────────────────────────────
// 2. Resolve signing key. The default is the path used when we ran
//    `tauri signer generate` — ~/.tauri/cubo-fraud-engine.key. Override with
//    TAURI_SIGNING_PRIVATE_KEY_PATH if the key lives elsewhere (e.g., in a
//    secure vault when running from CI later).
// ──────────────────────────────────────────────────────────────────────────
const homeDir = process.env.USERPROFILE || process.env.HOME || '';
const keyPath = process.env.TAURI_SIGNING_PRIVATE_KEY_PATH
  || join(homeDir, '.tauri', 'cubo-fraud-engine.key');

if (!existsSync(keyPath)) {
  console.error(`[release] Private key not found at: ${keyPath}`);
  console.error('         Generate one with: npx tauri signer generate -w <path>');
  console.error('         Or set TAURI_SIGNING_PRIVATE_KEY_PATH to point at an existing key.');
  process.exit(1);
}

// Resolve the signing password. Resolution order:
//   1. $TAURI_SIGNING_PRIVATE_KEY_PASSWORD set in the shell (use this in CI)
//   2. ~/.tauri/cubo-fraud-engine.password — a sibling file next to the
//      private key, OUTSIDE the repo (the standard local-dev path)
//
// The password is NOT hardcoded in source — it used to be, briefly, in an
// earlier version of this script. It now lives only on disk, alongside the
// private key it unlocks. Back BOTH files up together; losing either one
// breaks the auto-updater.
const passwordPath = keyPath.replace(/\.key$/, '.password');
let password = process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD;
if (!password) {
  if (!existsSync(passwordPath)) {
    console.error(
      `[release] No signing password available.\n` +
      `         Either set TAURI_SIGNING_PRIVATE_KEY_PASSWORD in your shell,\n` +
      `         or create ${passwordPath} containing just the password string.`,
    );
    process.exit(1);
  }
  password = readFileSync(passwordPath, 'utf8').trim();
}

// Both `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PATH` are
// supported by Tauri 2's CLI. Set both for defense-in-depth — different
// internal code paths read different names.
const env = {
  ...process.env,
  TAURI_SIGNING_PRIVATE_KEY:          keyPath,
  TAURI_SIGNING_PRIVATE_KEY_PATH:     keyPath,
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD: password,
};

console.log(`[release] Signing key:      ${keyPath}`);
console.log(`[release] Signing password: ${process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD ? '(from environment)' : `(from ${passwordPath})`}\n`);

// ──────────────────────────────────────────────────────────────────────────
// 3. Run the bundler. This is the slow part (8–15 min on a clean target/).
// ──────────────────────────────────────────────────────────────────────────
try {
  execSync('npm run tauri build', { cwd: desktopRoot, env, stdio: 'inherit' });
} catch (e) {
  console.error('\n[release] Build failed. See output above.');
  process.exit(1);
}

// ──────────────────────────────────────────────────────────────────────────
// 4. Locate the signed bundle and its detached signature.
// ──────────────────────────────────────────────────────────────────────────
const nsisDir = join(desktopRoot, 'src-tauri', 'target', 'release', 'bundle', 'nsis');
const exeName = `${productName}_${version}_x64-setup.exe`;
const exePath = join(nsisDir, exeName);
const sigPath = `${exePath}.sig`;

for (const required of [exePath, sigPath]) {
  if (!existsSync(required)) {
    console.error(`\n[release] Expected build output missing: ${required}`);
    console.error('          The build did not produce a signed bundle.');
    console.error('          Make sure the signing env vars resolved correctly.');
    process.exit(1);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// 5. Generate latest.json. This is what the auto-updater plugin reads from
//    the GitHub Releases /releases/latest/download/latest.json endpoint.
//    Format documented at https://v2.tauri.app/plugin/updater/
// ──────────────────────────────────────────────────────────────────────────
const repoUrl = 'https://github.com/jorgemelgar1/FraudEngine';
const tag = `v${version}`;

// GitHub Releases silently rewrites spaces in uploaded asset filenames to
// periods (so `Cubo Fraud Engine_0.1.0_x64-setup.exe` is served as
// `Cubo.Fraud.Engine_0.1.0_x64-setup.exe`). The URL we put in latest.json
// has to match GitHub's stored name, or the updater fetches the manifest,
// follows the URL inside, gets a 404, and silently refuses to update.
// Cost us a release cycle to figure out the first time — leaving this
// transform in place permanently.
const githubAssetName = exeName.replaceAll(' ', '.');
const exeUrl = `${repoUrl}/releases/download/${tag}/${githubAssetName}`;
const signature = readFileSync(sigPath, 'utf8').trim();

const latest = {
  version,
  notes: `Cubo Fraud Engine ${tag}`,
  pub_date: new Date().toISOString(),
  platforms: {
    'windows-x86_64': {
      signature,
      url: exeUrl,
    },
  },
};
const latestPath = join(nsisDir, 'latest.json');
writeFileSync(latestPath, JSON.stringify(latest, null, 2), 'utf8');

// ──────────────────────────────────────────────────────────────────────────
// 6. Print the upload steps so the release flow is fully scripted from the
//    user's perspective.
// ──────────────────────────────────────────────────────────────────────────
console.log('\n────────────────────────────────────────────────────────────────');
console.log('  Build complete. Three files are ready to ship:');
console.log('────────────────────────────────────────────────────────────────');
console.log(`  EXE       ${exePath}`);
console.log(`  SIG       ${sigPath}`);
console.log(`  MANIFEST  ${latestPath}`);
console.log('\nNEXT STEPS to publish the update:');
console.log(`  1. Open ${repoUrl}/releases/new`);
console.log(`  2. Tag:   ${tag}`);
console.log(`  3. Title: ${productName} ${tag}`);
console.log('  4. Description: a short summary of what changed in this version.');
console.log('  5. Drag all THREE files above into the "Attach binaries" area.');
console.log('  6. Make sure "Set as the latest release" is checked.');
console.log('  7. Click "Publish release".');
console.log('\nAfter that, every installed copy of the app will offer the update');
console.log('to its user on next launch.\n');
