// App Store Connect key authentication without storing credentials in this repo.
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StringDecoder } from 'node:string_decoder';

export const TEAM = 'PWCRJPY7YC';
export const APP = 'dev.keyvalet.mobile';
export const EXTENSION = `${APP}.KeyValetNSE`;
export const GROUP = 'group.dev.keyvalet.mobile';
const root = fileURLToPath(new URL('../../', import.meta.url));
const mobile = join(root, 'mobile');

export function parseCredentials(text, base) {
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const match = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || Object.hasOwn(values, match[1])) throw Error('Invalid ASC configuration');
    let value = match[2];
    if (/^(['"]).*\1$/.test(value)) value = value.slice(1, -1);
    values[match[1]] = value;
  }
  if (!/^[A-Z0-9]{10}$/.test(values.ASC_KEY_ID ?? '') ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(values.ASC_ISSUER_ID ?? '') ||
      !values.ASC_KEY_PATH || /[\r\n\0]/.test(values.ASC_KEY_PATH)) {
    throw Error('Missing ASC_KEY_ID, ASC_ISSUER_ID or ASC_KEY_PATH');
  }
  return {
    keyId: values.ASC_KEY_ID, issuerId: values.ASC_ISSUER_ID,
    keyPath: resolve(base, values.ASC_KEY_PATH.startsWith('~/')
      ? join(homedir(), values.ASC_KEY_PATH.slice(2)) : values.ASC_KEY_PATH),
  };
}

export function protectedFile(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0 || metadata.uid !== process.getuid()) {
    throw Error('ASC files must be owned by the current user and have mode 600');
  }
}

function credentials() {
  const file = process.env.KV_ASC_CREDENTIALS;
  if (!file) throw Error('Set KV_ASC_CREDENTIALS to the protected ASC configuration file');
  protectedFile(file);
  const config = parseCredentials(readFileSync(file, 'utf8'), process.env.KV_ASC_KEY_BASE ?? dirname(file));
  protectedFile(config.keyPath);
  return config;
}

export function authenticationArgs(config) {
  return ['-allowProvisioningUpdates', '-authenticationKeyPath', config.keyPath,
    '-authenticationKeyID', config.keyId, '-authenticationKeyIssuerID', config.issuerId];
}

export function redact(line, config) {
  for (const value of [config.keyId, config.issuerId, config.keyPath].sort((a, b) => b.length - a.length)) {
    line = line.split(value).join('[ASC redacted]');
    line = line.split(value.replaceAll(' ', '\\ ')).join('[ASC redacted]');
  }
  return /DART_DEFINES/i.test(line) ? '[DART_DEFINES redacted]\n' : line;
}

async function xcode(args) {
  if (args.some(arg => arg.startsWith('-authenticationKey') ||
      (arg.startsWith('DEVELOPMENT_TEAM=') && arg !== `DEVELOPMENT_TEAM=${TEAM}`))) {
    throw Error('Signing authentication and team cannot be overridden');
  }
  const config = credentials();
  const child = spawn('xcodebuild', [...args, ...authenticationArgs(config)], {
    cwd: mobile, stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (const [source, target] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
    const decoder = new StringDecoder('utf8');
    let pending = '';
    source.on('data', chunk => {
      pending += decoder.write(chunk);
      let end;
      while ((end = pending.indexOf('\n')) !== -1) {
        target.write(redact(pending.slice(0, end + 1), config));
        pending = pending.slice(end + 1);
      }
    });
    source.on('end', () => {
      pending += decoder.end();
      if (pending) target.write(redact(pending, config));
    });
  }
  const status = await new Promise((accept, reject) => {
    child.on('error', () => reject(Error('Cannot start xcodebuild')));
    child.on('close', code => accept(code ?? 1));
  });
  if (status !== 0) throw Error(`xcodebuild failed (${status})`);
}

function command(program, args, input) {
  try {
    return execFileSync(program, args, { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024 });
  } catch {
    throw Error(`Unable to verify signing metadata (${program})`);
  }
}

function plist(bytes) {
  return JSON.parse(command('python3', ['-c',
    'import datetime,json,plistlib,sys; print(json.dumps(plistlib.loads(sys.stdin.buffer.read()),default=lambda v:v.isoformat() if isinstance(v,datetime.datetime) else None))',
  ], bytes));
}

export function assertBundle(record, build) {
  const { info, entitlements, profile } = record;
  const id = info.CFBundleIdentifier;
  if (![APP, EXTENSION].includes(id) || info.CFBundleVersion !== build ||
      profile.TeamIdentifier?.[0] !== TEAM || !Number.isFinite(Date.parse(profile.ExpirationDate)) ||
      new Date(profile.ExpirationDate) <= new Date() ||
      profile.Entitlements?.['application-identifier'] !== `${TEAM}.${id}` ||
      entitlements['application-identifier'] !== `${TEAM}.${id}` ||
      entitlements['com.apple.developer.team-identifier'] !== TEAM ||
      entitlements['get-task-allow'] === true || profile.Entitlements?.['get-task-allow'] === true) {
    throw Error('Bundle, version, distribution profile or team does not match');
  }
  if (!Array.isArray(profile.Entitlements?.['com.apple.security.application-groups']) ||
      !profile.Entitlements['com.apple.security.application-groups'].includes(GROUP) ||
      !entitlements['com.apple.security.application-groups']?.includes(GROUP)) {
    throw Error('App Group is not authorized in both the signature and profile');
  }
  if (id === APP) {
    for (const value of [entitlements, profile.Entitlements]) {
      if (value['aps-environment'] !== 'production' ||
          value['com.apple.developer.devicecheck.appattest-environment'] !== 'production' ||
          value['com.apple.developer.usernotifications.time-sensitive'] !== true ||
          !value['com.apple.developer.applesignin']?.includes('Default')) {
        throw Error('Production push, App Attest, Apple sign-in or Time Sensitive entitlement missing');
      }
    }
  }
  if (profile.ProvisionedDevices || profile.ProvisionsAllDevices) {
    throw Error('TestFlight requires an App Store distribution profile');
  }
  return id;
}

function verifyApp(path, build) {
  const extensions = join(path, 'PlugIns');
  const children = existsSync(extensions) ? readdirSync(extensions).filter(name => name.endsWith('.appex')) : [];
  if (children.length !== 1) throw Error('Exactly one KeyValet notification extension is required');
  const ids = [];
  for (const bundle of [path, join(extensions, children[0])]) {
    command('codesign', ['--verify', '--deep', '--strict', bundle]);
    const info = plist(readFileSync(join(bundle, 'Info.plist')));
    const entitlements = plist(command('codesign', ['-d', '--entitlements', ':-', bundle]));
    const profile = plist(command('security', ['cms', '-D', '-i', join(bundle, 'embedded.mobileprovision')]));
    ids.push(assertBundle({ info, entitlements, profile }, build));
    const binary = join(bundle, info.CFBundleExecutable);
    if (!command('lipo', ['-archs', binary]).trim().split(/\s+/).includes('arm64') ||
        !/platform IOS\b/.test(command('vtool', ['-show-build', binary]))) {
      throw Error('A signed arm64 iOS device binary is required');
    }
  }
  if (ids[0] !== APP || ids[1] !== EXTENSION) throw Error('Unexpected archive bundles');
}

function verifyIpa(path, archiveApp) {
  const entries = command('unzip', ['-Z1', path]).split('\n').filter(Boolean);
  if (entries.some(name => name.startsWith('/') || name.split('/').includes('..'))) {
    throw Error('IPA contains unsafe paths');
  }
  const scratch = mkdtempSync(join(tmpdir(), 'keyvalet-ipa-'));
  try {
    command('ditto', ['-xk', path, scratch]);
    const apps = readdirSync(join(scratch, 'Payload')).filter(name => name.endsWith('.app'));
    if (apps.length !== 1) throw Error('IPA must contain exactly one app');
    const archive = plist(readFileSync(join(archiveApp, 'Info.plist')));
    const extracted = join(scratch, 'Payload', apps[0]);
    const actual = plist(readFileSync(join(extracted, 'Info.plist')));
    if (archive.CFBundleShortVersionString !== actual.CFBundleShortVersionString) {
      throw Error('Exported IPA does not match the archive version');
    }
    verifyApp(extracted, archive.CFBundleVersion);
  } finally { rmSync(scratch, { recursive: true }); }
}

export function exportOptions(options, destination) {
  if (options.teamID !== TEAM || options.method !== 'app-store-connect' ||
      options.signingStyle !== 'automatic' || !['export', 'upload'].includes(destination)) {
    throw Error('Expected automatic App Store Connect signing for the KeyValet team');
  }
  return { ...options, destination, manageAppVersionAndBuildNumber: false };
}

function treeHash(paths) {
  const digest = createHash('sha256');
  function visit(path) {
    const metadata = lstatSync(path);
    if (metadata.isDirectory()) {
      for (const name of readdirSync(path).sort()) visit(join(path, name));
    } else if (metadata.isFile()) {
      digest.update(path.replace(root, '')); digest.update('\0'); digest.update(readFileSync(path));
    } else if (metadata.isSymbolicLink()) {
      // The real versioned framework files are visited separately.
    } else {
      throw Error('Unexpected artifact file type');
    }
  }
  for (const path of paths) visit(path);
  return digest.digest('hex');
}

function sourceHash() {
  const paths = [join(root, 'rust/Cargo.lock'), join(root, 'rust/Cargo.toml')];
  for (const name of readdirSync(join(root, 'rust/crates')).sort()) {
    paths.push(join(root, 'rust/crates', name, 'Cargo.toml'), join(root, 'rust/crates', name, 'src'));
  }
  paths.push(join(mobile, 'lib'), join(mobile, 'pubspec.lock'), join(mobile, 'scripts'), join(mobile, 'packages/kv_native'),
    join(mobile, 'ios/Runner'), join(mobile, 'ios/KeyValetNSE'), join(mobile, 'ios/Runner.xcodeproj'),
    join(mobile, 'ios/Podfile'), join(mobile, 'ios/Podfile.lock'), join(mobile, 'native/ios'));
  return treeHash(paths);
}

async function main([action, ...args]) {
  if (action === 'credentials-check') { credentials(); console.log('Protected ASC configuration is ready.'); }
  else if (action === 'xcodebuild') await xcode(args);
  else if (action === 'verify-app') { verifyApp(args[0], args[1]); console.log('App and notification extension signing verified.'); }
  else if (action === 'verify-ipa') { verifyIpa(args[0], args[1]); console.log('Exported IPA signing verified.'); }
  else if (action === 'invalidate-build') { writeFileSync(args[0], JSON.stringify({ invalidated: true }), { mode: 0o600 }); }
  else if (action === 'export-options') {
    const options = exportOptions(plist(readFileSync(args[0])), args[2]);
    writeFileSync(args[1], command('python3', ['-c', 'import json,plistlib,sys; sys.stdout.buffer.write(plistlib.dumps(json.load(sys.stdin)))'], JSON.stringify(options)), { mode: 0o600 });
  } else if (action === 'snapshot') {
    writeFileSync(args[0], JSON.stringify({ source: sourceHash() }), { mode: 0o600 });
  } else if (action === 'seal-build') {
    const [ipa, app, snapshot, ready] = args;
    const before = JSON.parse(readFileSync(snapshot));
    if (before.source !== sourceHash()) throw Error('Sources changed during the archive; rebuild before uploading');
    writeFileSync(ready, JSON.stringify({ source: before.source, artifacts: treeHash([ipa, app]) }), { mode: 0o600 });
  } else if (action === 'verify-build') {
    const [ipa, app, ready] = args;
    const sealed = JSON.parse(readFileSync(ready));
    if (sealed.source !== sourceHash() || sealed.artifacts !== treeHash([ipa, app])) {
      throw Error('Archive, IPA or sources changed; rebuild before uploading');
    }
  } else throw Error('Use credentials-check, xcodebuild, verify-app, export-options, snapshot, seal-build or verify-build');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(() => { console.error('Signing step failed. Check provisioning and protected ASC configuration.'); process.exitCode = 1; });
}
