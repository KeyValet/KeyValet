Pod::Spec.new do |s|
  s.name = 'kv_native'
  s.version = '0.3.0'
  s.summary = 'Native KeyValet hardware keys and background core'
  s.homepage = 'https://github.com/keyvalet/keyvalet'
  s.license = { :type => 'Apache-2.0' }
  s.author = { 'KeyValet' => 'dev@keyvalet.invalid' }
  s.source = { :path => '.' }
  s.source_files = 'Classes/**/*.{swift,h}'
  s.public_header_files = 'Classes/Generated/kv_mobile.h'
  s.dependency 'Flutter'
  s.platform = :ios, '15.0'
  s.swift_version = '5.0'
  s.static_framework = true
  s.frameworks = 'CryptoKit', 'Security', 'LocalAuthentication', 'DeviceCheck', 'UserNotifications'
  s.vendored_frameworks = 'KvMobileCore.xcframework'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.user_target_xcconfig = { 'OTHER_LDFLAGS' => '$(inherited) -Wl,-u,_frb_get_rust_content_hash -Wl,-u,_frb_init_frb_dart_api_dl' }
end
