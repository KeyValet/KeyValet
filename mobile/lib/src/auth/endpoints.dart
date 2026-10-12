/// Product endpoints are fixed; provider client IDs are public relay metadata.
const keyValetRelayUrl = 'https://relay.keyvalet.dev/';
final keyValetAppleCallback = Uri.parse(
  keyValetRelayUrl,
).resolve('v1/account/apple/callback');
