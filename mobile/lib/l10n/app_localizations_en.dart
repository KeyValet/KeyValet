// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'KeyValet';

  @override
  String get pending => 'Pending';

  @override
  String get devices => 'Devices';

  @override
  String get activity => 'Activity';

  @override
  String get settings => 'Settings';

  @override
  String get connected => 'Connected';

  @override
  String get offline => 'Offline · signed changes stay queued';

  @override
  String get noPending => 'No approvals waiting';

  @override
  String get noDevices => 'Scan a device QR code to begin';

  @override
  String get noActivity => 'No issued actions yet';

  @override
  String get addDevice => 'Add device';

  @override
  String get allow => 'Allow';

  @override
  String get deny => 'Deny';

  @override
  String get cancel => 'Cancel';

  @override
  String get confirm => 'Confirm';

  @override
  String get save => 'Save';

  @override
  String get refresh => 'Refresh';

  @override
  String get allowOnce => 'Allow once';

  @override
  String get credentialScope => 'This credential';

  @override
  String get sessionScope => 'This session';

  @override
  String get remember1h => 'Remember for 1 hour';

  @override
  String get remember8h => 'Remember for 8 hours';

  @override
  String get remember24h => 'Remember for 24 hours';

  @override
  String get standingCredential => 'Always allow this credential';

  @override
  String get standingDevice => 'Always allow this device';

  @override
  String get scope => 'Approval scope';

  @override
  String get strong => 'Biometrics required to sign';

  @override
  String get quick => 'Phone must be unlocked';

  @override
  String get softwareWarning =>
      'This device uses software keys. Hardware protection is unavailable.';

  @override
  String get clockSkew => 'Device clocks differ. Check expiry carefully.';

  @override
  String get requester => 'Requesting device';

  @override
  String get agent => 'Agent';

  @override
  String get credential => 'Credential';

  @override
  String get operation => 'Operation';

  @override
  String get purpose => 'Agent stated purpose · unverified';

  @override
  String get risk => 'Risk';

  @override
  String get expiry => 'Expires';

  @override
  String get proxyOnly =>
      'Proxy access only; credential values stay on the executor';

  @override
  String get merged => 'Merged requests';

  @override
  String get noLongerWaiting => 'This approval is no longer waiting';

  @override
  String get issuedQueued => 'Signed and queued for delivery';

  @override
  String get securityUnavailable =>
      'Hardware keys are unavailable. Unlock the phone and enroll strong biometrics.';

  @override
  String get actionFailed =>
      'The action could not be completed. Refresh and try again.';

  @override
  String get starting => 'Opening secure storage…';

  @override
  String get scan => 'Scan QR code';

  @override
  String get pasteUri => 'Or paste kv-pair://';

  @override
  String get pairDevice => 'Pair device';

  @override
  String get compareSas => 'Compare these six digits on both devices';

  @override
  String get sasChecked => 'The digits match and I confirmed on the executor';

  @override
  String get globalWarning =>
      'Global grants also apply to newly paired devices.';

  @override
  String get excludeGlobal => 'Exclude this device from global grants';

  @override
  String get pairingExpired =>
      'Pairing expires soon. Generate a new QR code if needed.';

  @override
  String get mode => 'Approval mode';

  @override
  String get modePerUse => 'Ask every time';

  @override
  String get modeRemember => 'Remember for 1 hour';

  @override
  String get modeStanding => 'Always allow ordinary actions';

  @override
  String get grants => 'Standing grants and tickets';

  @override
  String get noGrants => 'No grants reported';

  @override
  String get source => 'Source';

  @override
  String get remainingBudget => 'Remaining calls';

  @override
  String get unknown => 'Awaiting device report';

  @override
  String get never => 'No expiry';

  @override
  String get queued => 'Pending delivery';

  @override
  String get issueTicket => 'Issue a 1 hour ticket';

  @override
  String get globalScope => 'All paired and future devices';

  @override
  String get globalScopeWarning =>
      'This includes future paired devices. Biometrics are required.';

  @override
  String get standing => 'No expiry · standing grant';

  @override
  String get unattended => 'Unattended sensitive operations';

  @override
  String get unattendedWarning =>
      'Sensitive operations can proceed without another prompt. This device only; expires in 7 days by default.';

  @override
  String get permanentWarning =>
      'A permanent sensitive grant has no automatic expiry. Confirm again to continue.';

  @override
  String get enterDeviceLabel => 'Type the device label to confirm';

  @override
  String get lockVault => 'Lock vault';

  @override
  String get revokeAll => 'Revoke all grants';

  @override
  String get revokeOne => 'Revoke grant';

  @override
  String get revokeDevice => 'Revoke device';

  @override
  String get revokeDeviceWarning =>
      'This removes the device from the account. Pair it again to reconnect.';

  @override
  String get recentActivity => 'Recent activity';

  @override
  String get relay => 'Relay address';

  @override
  String get notifications => 'Approval notifications';

  @override
  String get away => 'I am away from my computer';

  @override
  String get awayHint =>
      'Show alerts even when the executor initially sends silently.';

  @override
  String get exportDiagnostics => 'Copy diagnostics';

  @override
  String get diagnosticsHint =>
      'Counts and connection state only; no keys or approval content.';

  @override
  String get diagnosticsCopied => 'Diagnostics copied';

  @override
  String get language => 'Language';

  @override
  String get label => 'Label';

  @override
  String get protection => 'Key protection';

  @override
  String get continueAction => 'Continue';

  @override
  String get search => 'Search';

  @override
  String get signatureSource => 'Issued by this phone';

  @override
  String get scopeSensitiveHint =>
      'Sensitive requests can only be approved once.';

  @override
  String get confirmationMismatch => 'The label must match exactly';

  @override
  String get queryDetails => 'Query parameter names';

  @override
  String get bodyBytes => 'Body bytes';

  @override
  String get runtimeDetails => 'Runtime · working directory · user · PID';

  @override
  String get reason => 'Reason (optional)';

  @override
  String get grantIssued => 'Grant issued';

  @override
  String get devicePaired => 'Device paired';

  @override
  String get actionAllowed => 'Allowed';

  @override
  String get actionDenied => 'Denied';

  @override
  String get changeApplied => 'Applied';

  @override
  String get changeRejected => 'Rejected';

  @override
  String get invalidMessageRejected => 'Unverified message rejected';

  @override
  String get approvalOrigin => 'From an approval';

  @override
  String get softwareKeys => 'Software keys';

  @override
  String get executorActivity => 'Executor activity';

  @override
  String get controlCenter => 'CONTROL CENTER';

  @override
  String get pendingTitle => 'Your approvals';

  @override
  String get pendingSubtitle =>
      'See what is happening. Decide what happens next.';

  @override
  String get devicesTitle => 'Trusted devices';

  @override
  String get devicesSubtitle => 'Your executors, their access, your control.';

  @override
  String get activityTitle => 'Recent actions';

  @override
  String get activitySubtitle =>
      'A clear record of decisions issued by this phone.';

  @override
  String get settingsTitle => 'Preferences';

  @override
  String get settingsSubtitle => 'Stay connected, on your terms.';

  @override
  String get queueLabel => 'APPROVAL QUEUE';

  @override
  String get requestsWaiting => 'requests waiting';

  @override
  String get allCaughtUp => 'All caught up';

  @override
  String get allCaughtUpHint => 'New requests will appear here.';

  @override
  String pairedDevices(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count paired devices',
      one: '1 paired device',
    );
    return '$_temp0';
  }

  @override
  String sensitiveRequests(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count sensitive requests',
      one: '1 sensitive request',
    );
    return '$_temp0';
  }

  @override
  String get needsReview => 'Ready to review';

  @override
  String get riskReadOnly => 'Read only';

  @override
  String get riskOrdinary => 'Ordinary';

  @override
  String get riskSensitive => 'Sensitive';

  @override
  String get biometricTag => 'Biometrics';

  @override
  String get quickTag => 'Quick approval';

  @override
  String get escalatedTag => 'Escalated';

  @override
  String get silentTag => 'Silent';

  @override
  String get bannerTag => 'Alert';

  @override
  String get emptyPendingHint =>
      'Requests from your paired devices arrive here. Review each operation before you approve it.';

  @override
  String get firstDeviceHint =>
      'Pair your first executor to approve requests and manage access from your phone.';

  @override
  String get emptyActivityHint =>
      'Approvals, grants and device changes issued here will appear in this timeline.';

  @override
  String get pairingHint =>
      'Scan the QR code shown by KeyValet on your computer, then compare the six digits.';

  @override
  String get pairingCodeTitle => 'Confirm the connection';

  @override
  String get pasteSection => 'Have a pairing link?';

  @override
  String get connectionSection => 'CONNECTION';

  @override
  String get notificationsSection => 'NOTIFICATIONS';

  @override
  String get displaySection => 'DISPLAY';

  @override
  String get diagnosticsSection => 'DIAGNOSTICS';

  @override
  String get notificationHint =>
      'Receive alerts when a request needs your attention.';

  @override
  String get privacyTitle => 'Private by design';

  @override
  String get privacyHint =>
      'Credential values stay on the executor. Your phone receives approval details only.';

  @override
  String get onlineTag => 'Online';

  @override
  String get offlineTag => 'Offline';

  @override
  String get relayOnline => 'Relay online';

  @override
  String get relayOffline => 'Relay offline';

  @override
  String grantsCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count grants',
      one: '1 grant',
    );
    return '$_temp0';
  }

  @override
  String get delivered => 'Delivered';

  @override
  String get accessControls => 'Access controls';

  @override
  String get requestDetails => 'Request details';

  @override
  String get signingRequirement => 'Signing requirement';

  @override
  String get allowBiometric => 'Allow with biometrics';

  @override
  String unattendedCount(int count) {
    return 'Sensitive grants: $count';
  }

  @override
  String get requestedAt => 'Requested at';

  @override
  String unlockTimeout(int seconds) {
    return 'Unlock validity: $seconds s';
  }

  @override
  String get signInHeadline => 'Your approvals.\nIn your hands.';

  @override
  String get signInIntro =>
      'Connect your devices. Review each request. Stay in control.';

  @override
  String get signInDevices => 'Your devices';

  @override
  String get signInApproval => 'Biometric approvals';

  @override
  String get signInTitle => 'Welcome to KeyValet';

  @override
  String get signInSubtitle => 'Sign in to pair devices and manage approvals.';

  @override
  String get signInGoogle => 'Continue with Google';

  @override
  String get signInApple => 'Continue with Apple';

  @override
  String get signInPrivacy =>
      'Approval keys stay on your phone. Signing in never approves a request.';

  @override
  String get signInNotReady =>
      'Sign-in is not enabled on this relay yet. Try again after setup is complete.';

  @override
  String get signInNetworkError =>
      'Cannot reach the relay. Check your connection and try again.';

  @override
  String get signInRateLimited =>
      'Too many attempts. Please wait a moment and try again.';

  @override
  String get signInAccountConflict =>
      'This phone belongs to another account. Sign in with the account you used to set it up.';

  @override
  String get signInInvalidRelay => 'Enter an HTTPS relay address.';

  @override
  String get signInRelayBound =>
      'This phone is paired to its current relay. Remove paired devices before changing it.';

  @override
  String get signInFailed =>
      'Sign-in could not be completed. Please try again.';

  @override
  String get restoringSession => 'Checking your session…';

  @override
  String get signingIn => 'Signing in…';

  @override
  String get signInAccount => 'Signed-in account';

  @override
  String get signOut => 'Sign out';

  @override
  String get signOutHint =>
      'Approvals pause until you sign in again. Your paired devices and history stay on this phone.';
}
