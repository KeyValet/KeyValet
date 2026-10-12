// Public Rust display-model fixtures. There are no envelopes, key handles or cryptographic bytes.
import 'package:keyvalet_mobile/src/controller.dart';
import 'package:keyvalet_mobile/src/rust/view.dart';

const approval = ApprovalView(
  id: 'approval-1',
  kind: 'use',
  requesterId: 'executor-1',
  requesterLabel: 'CI executor',
  os: 'linux',
  protection: 'software_key',
  softwareWarning: true,
  runtime: 'codex',
  cwd: '/tmp/ci-repo',
  user: 'ci',
  agentPid: 42,
  credentialRef: 'github/default',
  credentialName: 'GitHub',
  credentialKind: 'static',
  proxyOnly: true,
  summary: 'Read GitHub profile',
  method: 'GET',
  host: 'api.github.com',
  path: '/user',
  queryKeys: ['page'],
  bodyBytes: 0,
  purpose: 'Check the profile',
  tier: 'T1',
  strong: false,
  scopeOptions: ['per_use', 'remember:1h', 'standing:credential'],
  requestedScope: 'per_use',
  mergedCount: 2,
  expiresAt: 1900000300,
  createdAt: 1900000000,
  clockSkew: false,
  banner: false,
  escalated: false,
);
const strongApproval = ApprovalView(
  id: 'approval-2',
  kind: 'use',
  requesterId: 'executor-1',
  requesterLabel: 'CI executor',
  os: 'linux',
  protection: 'software_key',
  softwareWarning: true,
  runtime: 'codex',
  cwd: '/tmp/ci-repo',
  user: 'ci',
  agentPid: 42,
  credentialRef: 'github/default',
  credentialName: 'GitHub',
  credentialKind: 'static',
  proxyOnly: true,
  summary: 'Delete a repository',
  method: 'DELETE',
  host: 'api.github.com',
  path: '/repos/demo',
  queryKeys: [],
  bodyBytes: 0,
  purpose: 'Remove a test repository',
  tier: 'T2',
  strong: true,
  scopeOptions: ['per_use'],
  requestedScope: 'per_use',
  mergedCount: 1,
  expiresAt: 1900000300,
  createdAt: 1900000000,
  clockSkew: false,
  banner: true,
  escalated: true,
);
const grantView = GrantView(
  id: 'grant-1',
  credential: 'github/default',
  level: 'credential',
  maxTier: 'T1',
  expiresAt: 1900003600,
  origin: 'settings',
  remainingCalls: 8,
  pendingDelivery: false,
);
const activityView = ActivityView(
  id: 'action-1',
  deviceId: 'executor-1',
  kind: 'grant',
  summary: 'Grant issued',
  at: 1900000000,
  delivered: true,
);
const device = DeviceView(
  id: 'executor-1',
  label: 'CI executor',
  os: 'linux',
  protection: 'software',
  online: true,
  mode: 'per_use',
  unlockTtlS: 300,
  unattended: false,
  unattendedCount: 0,
  grants: [grantView],
  recentActivity: [activityView],
);
const settings = SettingsView(
  relayUrl: 'https://relay.keyvalet.dev/',
  awayFromComputer: false,
  notifications: true,
  locale: 'en',
);

class FakeController extends MobileController {
  final List<String> intents = [];
  FakeController({
    String locale = 'en',
    bool empty = false,
    bool connected = true,
  }) {
    restoring = false;
    account = AccountView(
      signedIn: true,
      userId: 'test-user',
      provider: 'google',
      email: 'owner@example.test',
      displayName: 'Owner',
      expiresAt: 1900000000,
      relayUrl: settings.relayUrl,
      locale: locale,
      googleAvailable: true,
      appleAvailable: true,
    );
    state = Snapshot(
      pending: empty ? [] : [approval, strongApproval],
      devices: empty ? [] : [device],
      activity: empty ? [] : [activityView],
      settings: SettingsView(
        relayUrl: settings.relayUrl,
        awayFromComputer: false,
        notifications: true,
        locale: locale,
      ),
      connected: connected,
    );
  }
  @override
  Future<void> refresh() async {
    notifyListeners();
  }

  @override
  Future<void> decide(ApprovalView request, String scope, bool allow) async {
    intents.add('decide:${request.id}:$scope:$allow');
  }

  @override
  Future<void> directive(
    DeviceView device,
    String op, {
    String value = '',
    String confirmation = '',
  }) async {
    intents.add('$op:$value:$confirmation');
  }

  @override
  Future<void> grant(GrantInput input) async {
    intents.add(
      'grant:${input.hours}:${input.sensitive}:${input.confirmation}',
    );
  }

  @override
  Future<PairingView> beginPair(String uri) async {
    intents.add('pair:$uri');
    return const PairingView(
      pairingId: 'pair-1',
      peerLabel: 'CI executor',
      sas: '123456',
      expiresAt: 1900000300,
      globalGrants: 1,
    );
  }

  @override
  Future<void> confirmPair(PairingView pair, bool exclude) async {
    intents.add('confirm:${pair.sas}:$exclude');
  }

  @override
  Future<void> preferences({
    bool? away,
    bool? notifications,
    String? locale,
  }) async {
    intents.add('preferences:$away:$notifications:$locale');
  }

  @override
  Future<String> diagnostics() async => '{"schema":1,"paired_count":1}';
  @override
  void dispose() {
    state = null;
    super.dispose();
  }
}
