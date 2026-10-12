#!/usr/bin/env ruby
# Idempotently wires the standalone NSE and device-gate tests into the owned Xcode project.
require 'xcodeproj'
root = File.expand_path('..', __dir__)
project = Xcodeproj::Project.open(File.join(root, 'ios/Runner.xcodeproj'))
runner = project.targets.find { |target| target.name == 'Runner' }
nse = project.targets.find { |target| target.name == 'KeyValetNSE' } || project.new_target(:app_extension, 'KeyValetNSE', :ios, '15.0')
group = project.main_group.find_subpath('KeyValetNSE', true)
group.set_source_tree('<group>'); group.path = 'KeyValetNSE'
def source(group, target, path)
  reference = group.files.find { |file| file.path == path } || group.new_file(path)
  target.source_build_phase.add_file_reference(reference, true)
end
source(group, nse, 'NotificationService.swift')
source(group, nse, '../../packages/kv_native/ios/Classes/NativeRuntime.swift')
source(group, nse, '../../packages/kv_native/ios/Classes/KeyStore.swift')
# Source references above are relative to ios/KeyValetNSE.

library = project.main_group.files.find { |file| file.path == '../native/KvMobileCore.xcframework' } || project.main_group.new_file('../native/KvMobileCore.xcframework')
nse.frameworks_build_phase.files.to_a.each { |file| file.remove_from_project if file.file_ref == library }
runner.add_dependency(nse) unless runner.dependencies.any? { |dependency| dependency.target == nse }
embed = runner.copy_files_build_phases.find { |phase| phase.name == 'Embed App Extensions' } || runner.new_copy_files_build_phase('Embed App Extensions')
embed.dst_subfolder_spec = '13'
embedded = embed.add_file_reference(nse.product_reference, true)
embedded.settings = {'ATTRIBUTES' => ['RemoveHeadersOnCopy']}
runner.build_phases.delete(embed)
thin = runner.build_phases.find { |phase| phase.respond_to?(:name) && phase.name == 'Thin Binary' }
runner.build_phases.insert(thin ? runner.build_phases.index(thin) : runner.build_phases.length, embed)
project.targets.each do |target|
  target.build_configurations.each do |config|
    config.build_settings['DEVELOPMENT_TEAM'] = 'PWCRJPY7YC'
    config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.0'
    config.build_settings['ARCHS'] = 'arm64'
    config.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'i386 x86_64'
    if target == runner
      config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'dev.keyvalet.mobile'
      config.build_settings['CODE_SIGN_ENTITLEMENTS'] = config.name == 'Release' ? 'Runner/RunnerRelease.entitlements' : 'Runner/Runner.entitlements'
    elsif target == nse
      config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'dev.keyvalet.mobile.KeyValetNSE'
      config.build_settings['PRODUCT_NAME'] = 'KeyValetNSE'
      config.build_settings['PRODUCT_MODULE_NAME'] = 'KeyValetNSE'
      config.build_settings['LIBRARY_SEARCH_PATHS[sdk=iphoneos*]'] = ['$(inherited)', '$(SRCROOT)/../native/ios']
      config.build_settings['LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*]'] = ['$(inherited)', '$(SRCROOT)/../native/ios-sim']
      config.build_settings['OTHER_LDFLAGS'] = ['$(inherited)', '-lkv_mobile_core', '-framework', 'Security', '-lresolv']
      config.build_settings['INFOPLIST_FILE'] = 'KeyValetNSE/Info.plist'
      config.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'KeyValetNSE/KeyValetNSE.entitlements'
      config.build_settings['SWIFT_OBJC_BRIDGING_HEADER'] = 'KeyValetNSE/KeyValetNSE-Bridging-Header.h'
      config.build_settings['SWIFT_VERSION'] = '5.0'
      config.build_settings['APPLICATION_EXTENSION_API_ONLY'] = 'YES'
      config.build_settings['SKIP_INSTALL'] = 'YES'
      config.build_settings['TARGETED_DEVICE_FAMILY'] = '1,2'
      config.build_settings['CURRENT_PROJECT_VERSION'] = '1'
      config.build_settings['MARKETING_VERSION'] = '0.3.0'
    end
  end
end
tests = project.targets.find { |target| target.name == 'RunnerTests' }
source(project.main_group.find_subpath('RunnerTests', true), tests, 'StrongSigningGateTests.swift')
project.build_configurations.each { |config| config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.0' }
[[runner, project.main_group.find_subpath('Runner', true)], [nse, group]].each do |target, resources|
  variant = resources.children.find { |child| child.isa == 'PBXVariantGroup' && child.name == 'Localizable.strings' } || resources.new_variant_group('Localizable.strings')
  ['en', 'zh-Hans'].each do |locale|
    reference = variant.children.find { |child| child.name == locale } || variant.new_file("#{locale}.lproj/Localizable.strings")
    reference.name = locale
  end
  target.resources_build_phase.add_file_reference(variant, true)
end
project.save
