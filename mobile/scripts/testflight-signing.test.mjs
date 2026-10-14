import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { APP, EXTENSION, GROUP, TEAM, assertBundle, authenticationArgs, exportOptions, parseCredentials, protectedFile, redact } from './testflight-signing.mjs';

const configuration = 'ASC_KEY_ID=0123456789\nASC_ISSUER_ID=01234567-0123-0123-0123-0123456789ab\nASC_KEY_PATH=/private/example key.p8';

test('protected key authentication never sources config or prints credential metadata', () => {
  const config = parseCredentials(configuration, '/unused');
  assert.equal(config.keyPath, '/private/example key.p8');
  assert.deepEqual(authenticationArgs(config), ['-allowProvisioningUpdates', '-authenticationKeyPath', config.keyPath, '-authenticationKeyID', config.keyId, '-authenticationKeyIssuerID', config.issuerId]);
  for (const text of [config.keyId, config.issuerId, config.keyPath, config.keyPath.replaceAll(' ', '\\ ')]) {
    assert.equal(redact(text, config), '[ASC redacted]');
  }
  assert.equal(redact('DART_DEFINES=private', config), '[DART_DEFINES redacted]\n');
  for (const text of ['', 'source /private/x', configuration + '\nASC_KEY_ID=0123456789', configuration.replace('0123456789', 'bad'), configuration.replace('/private/example key.p8', 'x\0y')]) {
    assert.throws(() => parseCredentials(text, '/unused'));
  }
  assert.equal(parseCredentials(configuration.replace('/private/example key.p8', '"../key.p8"'), '/config/mobile').keyPath, '/config/key.p8');
});

test('credential files reject symlinks and broad permissions', () => {
  const directory = mkdtempSync(join(tmpdir(), 'keyvalet-signing-'));
  try {
    const file = join(directory, 'key');
    writeFileSync(file, 'fixture', { mode: 0o600 });
    protectedFile(file);
    chmodSync(file, 0o640);
    assert.throws(() => protectedFile(file));
    chmodSync(file, 0o600);
    symlinkSync(file, join(directory, 'link'));
    assert.throws(() => protectedFile(join(directory, 'link')));
  } finally { rmSync(directory, { recursive: true }); }
});

function fixture(id) {
  const entitlements = {
    'application-identifier': `${TEAM}.${id}`, 'com.apple.developer.team-identifier': TEAM,
    'get-task-allow': false, 'com.apple.security.application-groups': [GROUP],
  };
  if (id === APP) Object.assign(entitlements, {
    'aps-environment': 'production', 'com.apple.developer.devicecheck.appattest-environment': 'production',
    'com.apple.developer.usernotifications.time-sensitive': true, 'com.apple.developer.applesignin': ['Default'],
  });
  return { info: { CFBundleIdentifier: id, CFBundleVersion: '1' }, entitlements,
    profile: { TeamIdentifier: [TEAM], ExpirationDate: '2099-01-01', Entitlements: structuredClone(entitlements) } };
}

test('app and extension must both authorize the actual production App Group', () => {
  assert.equal(assertBundle(fixture(APP), '1'), APP);
  assert.equal(assertBundle(fixture(EXTENSION), '1'), EXTENSION);
  for (const mutate of [
    record => { record.info.CFBundleVersion = '2'; },
    record => { record.info.CFBundleIdentifier = 'com.simvito.app'; },
    record => { record.profile.TeamIdentifier = ['OTHER']; },
    record => { record.profile.ExpirationDate = '2000-01-01'; },
    record => { delete record.profile.ExpirationDate; },
    record => { record.profile.Entitlements['application-identifier'] = `${TEAM}.*`; },
    record => { record.entitlements['get-task-allow'] = true; },
    record => { record.profile.Entitlements['get-task-allow'] = true; },
    record => { record.profile.ProvisionedDevices = ['fixture']; },
    record => { record.profile.ProvisionsAllDevices = true; },
    record => { record.entitlements['com.apple.security.application-groups'] = ['group.com.simvito.app']; },
    record => { record.profile.Entitlements['com.apple.security.application-groups'] = []; },
  ]) {
    const record = fixture(APP); mutate(record); assert.throws(() => assertBundle(record, '1'));
  }
  for (const key of ['aps-environment', 'com.apple.developer.devicecheck.appattest-environment', 'com.apple.developer.usernotifications.time-sensitive', 'com.apple.developer.applesignin']) {
    for (const section of ['entitlements', 'profile']) {
      const record = fixture(APP);
      delete (section === 'profile' ? record.profile.Entitlements : record.entitlements)[key];
      assert.throws(() => assertBundle(record, '1'));
    }
  }
});

test('export stays local until an explicit upload and never changes build numbers', () => {
  const options = { teamID: TEAM, method: 'app-store-connect', signingStyle: 'automatic', destination: 'upload' };
  assert.equal(exportOptions(options, 'export').destination, 'export');
  assert.equal(exportOptions(options, 'upload').manageAppVersionAndBuildNumber, false);
  for (const value of [ { ...options, teamID: 'OTHER' }, { ...options, method: 'development' }, { ...options, signingStyle: 'manual' }]) {
    assert.throws(() => exportOptions(value, 'export'));
  }
  assert.throws(() => exportOptions(options, 'other'));
});
