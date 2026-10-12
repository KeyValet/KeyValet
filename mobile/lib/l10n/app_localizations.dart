import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_zh.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('zh'),
  ];

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'KeyValet'**
  String get appTitle;

  /// No description provided for @pending.
  ///
  /// In en, this message translates to:
  /// **'Pending'**
  String get pending;

  /// No description provided for @devices.
  ///
  /// In en, this message translates to:
  /// **'Devices'**
  String get devices;

  /// No description provided for @activity.
  ///
  /// In en, this message translates to:
  /// **'Activity'**
  String get activity;

  /// No description provided for @settings.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get settings;

  /// No description provided for @connected.
  ///
  /// In en, this message translates to:
  /// **'Connected'**
  String get connected;

  /// No description provided for @offline.
  ///
  /// In en, this message translates to:
  /// **'Offline · signed changes stay queued'**
  String get offline;

  /// No description provided for @noPending.
  ///
  /// In en, this message translates to:
  /// **'No approvals waiting'**
  String get noPending;

  /// No description provided for @noDevices.
  ///
  /// In en, this message translates to:
  /// **'Scan a device QR code to begin'**
  String get noDevices;

  /// No description provided for @noActivity.
  ///
  /// In en, this message translates to:
  /// **'No issued actions yet'**
  String get noActivity;

  /// No description provided for @addDevice.
  ///
  /// In en, this message translates to:
  /// **'Add device'**
  String get addDevice;

  /// No description provided for @allow.
  ///
  /// In en, this message translates to:
  /// **'Allow'**
  String get allow;

  /// No description provided for @deny.
  ///
  /// In en, this message translates to:
  /// **'Deny'**
  String get deny;

  /// No description provided for @cancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// No description provided for @confirm.
  ///
  /// In en, this message translates to:
  /// **'Confirm'**
  String get confirm;

  /// No description provided for @save.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// No description provided for @refresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get refresh;

  /// No description provided for @allowOnce.
  ///
  /// In en, this message translates to:
  /// **'Allow once'**
  String get allowOnce;

  /// No description provided for @credentialScope.
  ///
  /// In en, this message translates to:
  /// **'This credential'**
  String get credentialScope;

  /// No description provided for @sessionScope.
  ///
  /// In en, this message translates to:
  /// **'This session'**
  String get sessionScope;

  /// No description provided for @remember1h.
  ///
  /// In en, this message translates to:
  /// **'Remember for 1 hour'**
  String get remember1h;

  /// No description provided for @remember8h.
  ///
  /// In en, this message translates to:
  /// **'Remember for 8 hours'**
  String get remember8h;

  /// No description provided for @remember24h.
  ///
  /// In en, this message translates to:
  /// **'Remember for 24 hours'**
  String get remember24h;

  /// No description provided for @standingCredential.
  ///
  /// In en, this message translates to:
  /// **'Always allow this credential'**
  String get standingCredential;

  /// No description provided for @standingDevice.
  ///
  /// In en, this message translates to:
  /// **'Always allow this device'**
  String get standingDevice;

  /// No description provided for @scope.
  ///
  /// In en, this message translates to:
  /// **'Approval scope'**
  String get scope;

  /// No description provided for @strong.
  ///
  /// In en, this message translates to:
  /// **'Biometrics required to sign'**
  String get strong;

  /// No description provided for @quick.
  ///
  /// In en, this message translates to:
  /// **'Phone must be unlocked'**
  String get quick;

  /// No description provided for @softwareWarning.
  ///
  /// In en, this message translates to:
  /// **'This device uses software keys. Hardware protection is unavailable.'**
  String get softwareWarning;

  /// No description provided for @clockSkew.
  ///
  /// In en, this message translates to:
  /// **'Device clocks differ. Check expiry carefully.'**
  String get clockSkew;

  /// No description provided for @requester.
  ///
  /// In en, this message translates to:
  /// **'Requesting device'**
  String get requester;

  /// No description provided for @agent.
  ///
  /// In en, this message translates to:
  /// **'Agent'**
  String get agent;

  /// No description provided for @credential.
  ///
  /// In en, this message translates to:
  /// **'Credential'**
  String get credential;

  /// No description provided for @operation.
  ///
  /// In en, this message translates to:
  /// **'Operation'**
  String get operation;

  /// No description provided for @purpose.
  ///
  /// In en, this message translates to:
  /// **'Agent stated purpose · unverified'**
  String get purpose;

  /// No description provided for @risk.
  ///
  /// In en, this message translates to:
  /// **'Risk'**
  String get risk;

  /// No description provided for @expiry.
  ///
  /// In en, this message translates to:
  /// **'Expires'**
  String get expiry;

  /// No description provided for @proxyOnly.
  ///
  /// In en, this message translates to:
  /// **'Proxy access only; credential values stay on the executor'**
  String get proxyOnly;

  /// No description provided for @merged.
  ///
  /// In en, this message translates to:
  /// **'Merged requests'**
  String get merged;

  /// No description provided for @noLongerWaiting.
  ///
  /// In en, this message translates to:
  /// **'This approval is no longer waiting'**
  String get noLongerWaiting;

  /// No description provided for @issuedQueued.
  ///
  /// In en, this message translates to:
  /// **'Signed and queued for delivery'**
  String get issuedQueued;

  /// No description provided for @securityUnavailable.
  ///
  /// In en, this message translates to:
  /// **'Hardware keys are unavailable. Unlock the phone and enroll strong biometrics.'**
  String get securityUnavailable;

  /// No description provided for @actionFailed.
  ///
  /// In en, this message translates to:
  /// **'The action could not be completed. Refresh and try again.'**
  String get actionFailed;

  /// No description provided for @starting.
  ///
  /// In en, this message translates to:
  /// **'Opening secure storage…'**
  String get starting;

  /// No description provided for @scan.
  ///
  /// In en, this message translates to:
  /// **'Scan QR code'**
  String get scan;

  /// No description provided for @pasteUri.
  ///
  /// In en, this message translates to:
  /// **'Or paste kv-pair://'**
  String get pasteUri;

  /// No description provided for @pairDevice.
  ///
  /// In en, this message translates to:
  /// **'Pair device'**
  String get pairDevice;

  /// No description provided for @compareSas.
  ///
  /// In en, this message translates to:
  /// **'Compare these six digits on both devices'**
  String get compareSas;

  /// No description provided for @sasChecked.
  ///
  /// In en, this message translates to:
  /// **'The digits match and I confirmed on the executor'**
  String get sasChecked;

  /// No description provided for @globalWarning.
  ///
  /// In en, this message translates to:
  /// **'Global grants also apply to newly paired devices.'**
  String get globalWarning;

  /// No description provided for @excludeGlobal.
  ///
  /// In en, this message translates to:
  /// **'Exclude this device from global grants'**
  String get excludeGlobal;

  /// No description provided for @pairingExpired.
  ///
  /// In en, this message translates to:
  /// **'Pairing expires soon. Generate a new QR code if needed.'**
  String get pairingExpired;

  /// No description provided for @mode.
  ///
  /// In en, this message translates to:
  /// **'Approval mode'**
  String get mode;

  /// No description provided for @modePerUse.
  ///
  /// In en, this message translates to:
  /// **'Ask every time'**
  String get modePerUse;

  /// No description provided for @modeRemember.
  ///
  /// In en, this message translates to:
  /// **'Remember for 1 hour'**
  String get modeRemember;

  /// No description provided for @modeStanding.
  ///
  /// In en, this message translates to:
  /// **'Always allow ordinary actions'**
  String get modeStanding;

  /// No description provided for @grants.
  ///
  /// In en, this message translates to:
  /// **'Standing grants and tickets'**
  String get grants;

  /// No description provided for @noGrants.
  ///
  /// In en, this message translates to:
  /// **'No grants reported'**
  String get noGrants;

  /// No description provided for @source.
  ///
  /// In en, this message translates to:
  /// **'Source'**
  String get source;

  /// No description provided for @remainingBudget.
  ///
  /// In en, this message translates to:
  /// **'Remaining calls'**
  String get remainingBudget;

  /// No description provided for @unknown.
  ///
  /// In en, this message translates to:
  /// **'Awaiting device report'**
  String get unknown;

  /// No description provided for @never.
  ///
  /// In en, this message translates to:
  /// **'No expiry'**
  String get never;

  /// No description provided for @queued.
  ///
  /// In en, this message translates to:
  /// **'Pending delivery'**
  String get queued;

  /// No description provided for @issueTicket.
  ///
  /// In en, this message translates to:
  /// **'Issue a 1 hour ticket'**
  String get issueTicket;

  /// No description provided for @globalScope.
  ///
  /// In en, this message translates to:
  /// **'All paired and future devices'**
  String get globalScope;

  /// No description provided for @globalScopeWarning.
  ///
  /// In en, this message translates to:
  /// **'This includes future paired devices. Biometrics are required.'**
  String get globalScopeWarning;

  /// No description provided for @standing.
  ///
  /// In en, this message translates to:
  /// **'No expiry · standing grant'**
  String get standing;

  /// No description provided for @unattended.
  ///
  /// In en, this message translates to:
  /// **'Unattended sensitive operations'**
  String get unattended;

  /// No description provided for @unattendedWarning.
  ///
  /// In en, this message translates to:
  /// **'Sensitive operations can proceed without another prompt. This device only; expires in 7 days by default.'**
  String get unattendedWarning;

  /// No description provided for @permanentWarning.
  ///
  /// In en, this message translates to:
  /// **'A permanent sensitive grant has no automatic expiry. Confirm again to continue.'**
  String get permanentWarning;

  /// No description provided for @enterDeviceLabel.
  ///
  /// In en, this message translates to:
  /// **'Type the device label to confirm'**
  String get enterDeviceLabel;

  /// No description provided for @lockVault.
  ///
  /// In en, this message translates to:
  /// **'Lock vault'**
  String get lockVault;

  /// No description provided for @revokeAll.
  ///
  /// In en, this message translates to:
  /// **'Revoke all grants'**
  String get revokeAll;

  /// No description provided for @revokeOne.
  ///
  /// In en, this message translates to:
  /// **'Revoke grant'**
  String get revokeOne;

  /// No description provided for @revokeDevice.
  ///
  /// In en, this message translates to:
  /// **'Revoke device'**
  String get revokeDevice;

  /// No description provided for @revokeDeviceWarning.
  ///
  /// In en, this message translates to:
  /// **'This removes the device from the account. Pair it again to reconnect.'**
  String get revokeDeviceWarning;

  /// No description provided for @recentActivity.
  ///
  /// In en, this message translates to:
  /// **'Recent activity'**
  String get recentActivity;

  /// No description provided for @relay.
  ///
  /// In en, this message translates to:
  /// **'Relay address'**
  String get relay;

  /// No description provided for @notifications.
  ///
  /// In en, this message translates to:
  /// **'Approval notifications'**
  String get notifications;

  /// No description provided for @away.
  ///
  /// In en, this message translates to:
  /// **'I am away from my computer'**
  String get away;

  /// No description provided for @awayHint.
  ///
  /// In en, this message translates to:
  /// **'Show alerts even when the executor initially sends silently.'**
  String get awayHint;

  /// No description provided for @exportDiagnostics.
  ///
  /// In en, this message translates to:
  /// **'Copy diagnostics'**
  String get exportDiagnostics;

  /// No description provided for @diagnosticsHint.
  ///
  /// In en, this message translates to:
  /// **'Counts and connection state only; no keys or approval content.'**
  String get diagnosticsHint;

  /// No description provided for @diagnosticsCopied.
  ///
  /// In en, this message translates to:
  /// **'Diagnostics copied'**
  String get diagnosticsCopied;

  /// No description provided for @language.
  ///
  /// In en, this message translates to:
  /// **'Language'**
  String get language;

  /// No description provided for @label.
  ///
  /// In en, this message translates to:
  /// **'Label'**
  String get label;

  /// No description provided for @protection.
  ///
  /// In en, this message translates to:
  /// **'Key protection'**
  String get protection;

  /// No description provided for @continueAction.
  ///
  /// In en, this message translates to:
  /// **'Continue'**
  String get continueAction;

  /// No description provided for @search.
  ///
  /// In en, this message translates to:
  /// **'Search'**
  String get search;

  /// No description provided for @signatureSource.
  ///
  /// In en, this message translates to:
  /// **'Issued by this phone'**
  String get signatureSource;

  /// No description provided for @scopeSensitiveHint.
  ///
  /// In en, this message translates to:
  /// **'Sensitive requests can only be approved once.'**
  String get scopeSensitiveHint;

  /// No description provided for @confirmationMismatch.
  ///
  /// In en, this message translates to:
  /// **'The label must match exactly'**
  String get confirmationMismatch;

  /// No description provided for @queryDetails.
  ///
  /// In en, this message translates to:
  /// **'Query parameter names'**
  String get queryDetails;

  /// No description provided for @bodyBytes.
  ///
  /// In en, this message translates to:
  /// **'Body bytes'**
  String get bodyBytes;

  /// No description provided for @runtimeDetails.
  ///
  /// In en, this message translates to:
  /// **'Runtime · working directory · user · PID'**
  String get runtimeDetails;

  /// No description provided for @reason.
  ///
  /// In en, this message translates to:
  /// **'Reason (optional)'**
  String get reason;

  /// No description provided for @grantIssued.
  ///
  /// In en, this message translates to:
  /// **'Grant issued'**
  String get grantIssued;

  /// No description provided for @devicePaired.
  ///
  /// In en, this message translates to:
  /// **'Device paired'**
  String get devicePaired;

  /// No description provided for @actionAllowed.
  ///
  /// In en, this message translates to:
  /// **'Allowed'**
  String get actionAllowed;

  /// No description provided for @actionDenied.
  ///
  /// In en, this message translates to:
  /// **'Denied'**
  String get actionDenied;

  /// No description provided for @changeApplied.
  ///
  /// In en, this message translates to:
  /// **'Applied'**
  String get changeApplied;

  /// No description provided for @changeRejected.
  ///
  /// In en, this message translates to:
  /// **'Rejected'**
  String get changeRejected;

  /// No description provided for @invalidMessageRejected.
  ///
  /// In en, this message translates to:
  /// **'Unverified message rejected'**
  String get invalidMessageRejected;

  /// No description provided for @approvalOrigin.
  ///
  /// In en, this message translates to:
  /// **'From an approval'**
  String get approvalOrigin;

  /// No description provided for @softwareKeys.
  ///
  /// In en, this message translates to:
  /// **'Software keys'**
  String get softwareKeys;

  /// No description provided for @executorActivity.
  ///
  /// In en, this message translates to:
  /// **'Executor activity'**
  String get executorActivity;

  /// No description provided for @controlCenter.
  ///
  /// In en, this message translates to:
  /// **'CONTROL CENTER'**
  String get controlCenter;

  /// No description provided for @pendingTitle.
  ///
  /// In en, this message translates to:
  /// **'Your approvals'**
  String get pendingTitle;

  /// No description provided for @pendingSubtitle.
  ///
  /// In en, this message translates to:
  /// **'See what is happening. Decide what happens next.'**
  String get pendingSubtitle;

  /// No description provided for @devicesTitle.
  ///
  /// In en, this message translates to:
  /// **'Trusted devices'**
  String get devicesTitle;

  /// No description provided for @devicesSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Your executors, their access, your control.'**
  String get devicesSubtitle;

  /// No description provided for @activityTitle.
  ///
  /// In en, this message translates to:
  /// **'Recent actions'**
  String get activityTitle;

  /// No description provided for @activitySubtitle.
  ///
  /// In en, this message translates to:
  /// **'A clear record of decisions issued by this phone.'**
  String get activitySubtitle;

  /// No description provided for @settingsTitle.
  ///
  /// In en, this message translates to:
  /// **'Preferences'**
  String get settingsTitle;

  /// No description provided for @settingsSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Stay connected, on your terms.'**
  String get settingsSubtitle;

  /// No description provided for @queueLabel.
  ///
  /// In en, this message translates to:
  /// **'APPROVAL QUEUE'**
  String get queueLabel;

  /// No description provided for @requestsWaiting.
  ///
  /// In en, this message translates to:
  /// **'requests waiting'**
  String get requestsWaiting;

  /// No description provided for @allCaughtUp.
  ///
  /// In en, this message translates to:
  /// **'All caught up'**
  String get allCaughtUp;

  /// No description provided for @allCaughtUpHint.
  ///
  /// In en, this message translates to:
  /// **'New requests will appear here.'**
  String get allCaughtUpHint;

  /// No description provided for @pairedDevices.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 paired device} other{{count} paired devices}}'**
  String pairedDevices(int count);

  /// No description provided for @sensitiveRequests.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 sensitive request} other{{count} sensitive requests}}'**
  String sensitiveRequests(int count);

  /// No description provided for @needsReview.
  ///
  /// In en, this message translates to:
  /// **'Ready to review'**
  String get needsReview;

  /// No description provided for @riskReadOnly.
  ///
  /// In en, this message translates to:
  /// **'Read only'**
  String get riskReadOnly;

  /// No description provided for @riskOrdinary.
  ///
  /// In en, this message translates to:
  /// **'Ordinary'**
  String get riskOrdinary;

  /// No description provided for @riskSensitive.
  ///
  /// In en, this message translates to:
  /// **'Sensitive'**
  String get riskSensitive;

  /// No description provided for @biometricTag.
  ///
  /// In en, this message translates to:
  /// **'Biometrics'**
  String get biometricTag;

  /// No description provided for @quickTag.
  ///
  /// In en, this message translates to:
  /// **'Quick approval'**
  String get quickTag;

  /// No description provided for @escalatedTag.
  ///
  /// In en, this message translates to:
  /// **'Escalated'**
  String get escalatedTag;

  /// No description provided for @silentTag.
  ///
  /// In en, this message translates to:
  /// **'Silent'**
  String get silentTag;

  /// No description provided for @bannerTag.
  ///
  /// In en, this message translates to:
  /// **'Alert'**
  String get bannerTag;

  /// No description provided for @emptyPendingHint.
  ///
  /// In en, this message translates to:
  /// **'Requests from your paired devices arrive here. Review each operation before you approve it.'**
  String get emptyPendingHint;

  /// No description provided for @firstDeviceHint.
  ///
  /// In en, this message translates to:
  /// **'Pair your first executor to approve requests and manage access from your phone.'**
  String get firstDeviceHint;

  /// No description provided for @emptyActivityHint.
  ///
  /// In en, this message translates to:
  /// **'Approvals, grants and device changes issued here will appear in this timeline.'**
  String get emptyActivityHint;

  /// No description provided for @pairingHint.
  ///
  /// In en, this message translates to:
  /// **'Scan the QR code shown by KeyValet on your computer, then compare the six digits.'**
  String get pairingHint;

  /// No description provided for @pairingCodeTitle.
  ///
  /// In en, this message translates to:
  /// **'Confirm the connection'**
  String get pairingCodeTitle;

  /// No description provided for @pasteSection.
  ///
  /// In en, this message translates to:
  /// **'Have a pairing link?'**
  String get pasteSection;

  /// No description provided for @connectionSection.
  ///
  /// In en, this message translates to:
  /// **'CONNECTION'**
  String get connectionSection;

  /// No description provided for @notificationsSection.
  ///
  /// In en, this message translates to:
  /// **'NOTIFICATIONS'**
  String get notificationsSection;

  /// No description provided for @displaySection.
  ///
  /// In en, this message translates to:
  /// **'DISPLAY'**
  String get displaySection;

  /// No description provided for @diagnosticsSection.
  ///
  /// In en, this message translates to:
  /// **'DIAGNOSTICS'**
  String get diagnosticsSection;

  /// No description provided for @notificationHint.
  ///
  /// In en, this message translates to:
  /// **'Receive alerts when a request needs your attention.'**
  String get notificationHint;

  /// No description provided for @privacyTitle.
  ///
  /// In en, this message translates to:
  /// **'Private by design'**
  String get privacyTitle;

  /// No description provided for @privacyHint.
  ///
  /// In en, this message translates to:
  /// **'Credential values stay on the executor. Your phone receives approval details only.'**
  String get privacyHint;

  /// No description provided for @onlineTag.
  ///
  /// In en, this message translates to:
  /// **'Online'**
  String get onlineTag;

  /// No description provided for @offlineTag.
  ///
  /// In en, this message translates to:
  /// **'Offline'**
  String get offlineTag;

  /// No description provided for @relayOnline.
  ///
  /// In en, this message translates to:
  /// **'Relay online'**
  String get relayOnline;

  /// No description provided for @relayOffline.
  ///
  /// In en, this message translates to:
  /// **'Relay offline'**
  String get relayOffline;

  /// No description provided for @grantsCount.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 grant} other{{count} grants}}'**
  String grantsCount(int count);

  /// No description provided for @delivered.
  ///
  /// In en, this message translates to:
  /// **'Delivered'**
  String get delivered;

  /// No description provided for @accessControls.
  ///
  /// In en, this message translates to:
  /// **'Access controls'**
  String get accessControls;

  /// No description provided for @requestDetails.
  ///
  /// In en, this message translates to:
  /// **'Request details'**
  String get requestDetails;

  /// No description provided for @signingRequirement.
  ///
  /// In en, this message translates to:
  /// **'Signing requirement'**
  String get signingRequirement;

  /// No description provided for @allowBiometric.
  ///
  /// In en, this message translates to:
  /// **'Allow with biometrics'**
  String get allowBiometric;

  /// No description provided for @unattendedCount.
  ///
  /// In en, this message translates to:
  /// **'Sensitive grants: {count}'**
  String unattendedCount(int count);

  /// No description provided for @requestedAt.
  ///
  /// In en, this message translates to:
  /// **'Requested at'**
  String get requestedAt;

  /// No description provided for @unlockTimeout.
  ///
  /// In en, this message translates to:
  /// **'Unlock validity: {seconds} s'**
  String unlockTimeout(int seconds);

  /// No description provided for @signInHeadline.
  ///
  /// In en, this message translates to:
  /// **'Your approvals.\nIn your hands.'**
  String get signInHeadline;

  /// No description provided for @signInIntro.
  ///
  /// In en, this message translates to:
  /// **'Connect your devices. Review each request. Stay in control.'**
  String get signInIntro;

  /// No description provided for @signInDevices.
  ///
  /// In en, this message translates to:
  /// **'Your devices'**
  String get signInDevices;

  /// No description provided for @signInApproval.
  ///
  /// In en, this message translates to:
  /// **'Biometric approvals'**
  String get signInApproval;

  /// No description provided for @signInTitle.
  ///
  /// In en, this message translates to:
  /// **'Welcome to KeyValet'**
  String get signInTitle;

  /// No description provided for @signInSubtitle.
  ///
  /// In en, this message translates to:
  /// **'Sign in to pair devices and manage approvals.'**
  String get signInSubtitle;

  /// No description provided for @signInGoogle.
  ///
  /// In en, this message translates to:
  /// **'Continue with Google'**
  String get signInGoogle;

  /// No description provided for @signInApple.
  ///
  /// In en, this message translates to:
  /// **'Continue with Apple'**
  String get signInApple;

  /// No description provided for @signInPrivacy.
  ///
  /// In en, this message translates to:
  /// **'Approval keys stay on your phone. Signing in never approves a request.'**
  String get signInPrivacy;

  /// No description provided for @signInNotReady.
  ///
  /// In en, this message translates to:
  /// **'Sign-in is not enabled on this relay yet. Try again after setup is complete.'**
  String get signInNotReady;

  /// No description provided for @signInNetworkError.
  ///
  /// In en, this message translates to:
  /// **'Cannot reach the relay. Check your connection and try again.'**
  String get signInNetworkError;

  /// No description provided for @signInRateLimited.
  ///
  /// In en, this message translates to:
  /// **'Too many attempts. Please wait a moment and try again.'**
  String get signInRateLimited;

  /// No description provided for @signInAccountConflict.
  ///
  /// In en, this message translates to:
  /// **'This phone belongs to another account. Sign in with the account you used to set it up.'**
  String get signInAccountConflict;

  /// No description provided for @signInInvalidRelay.
  ///
  /// In en, this message translates to:
  /// **'Enter an HTTPS relay address.'**
  String get signInInvalidRelay;

  /// No description provided for @signInRelayBound.
  ///
  /// In en, this message translates to:
  /// **'This phone is paired to its current relay. Remove paired devices before changing it.'**
  String get signInRelayBound;

  /// No description provided for @signInFailed.
  ///
  /// In en, this message translates to:
  /// **'Sign-in could not be completed. Please try again.'**
  String get signInFailed;

  /// No description provided for @restoringSession.
  ///
  /// In en, this message translates to:
  /// **'Checking your session…'**
  String get restoringSession;

  /// No description provided for @signingIn.
  ///
  /// In en, this message translates to:
  /// **'Signing in…'**
  String get signingIn;

  /// No description provided for @signInAccount.
  ///
  /// In en, this message translates to:
  /// **'Signed-in account'**
  String get signInAccount;

  /// No description provided for @signOut.
  ///
  /// In en, this message translates to:
  /// **'Sign out'**
  String get signOut;

  /// No description provided for @signOutHint.
  ///
  /// In en, this message translates to:
  /// **'Approvals pause until you sign in again. Your paired devices and history stay on this phone.'**
  String get signOutHint;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'zh'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'zh':
      return AppLocalizationsZh();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
