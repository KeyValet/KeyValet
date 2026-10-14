#!/usr/bin/env python3
"""Read-only Security.framework probe of our own installed CLI process.

The child is held at stdin with no recovery input. No helper operation, relay
request, key creation/signing, or UI is issued. Only signature status and public
code paths are printed. The child is terminated and reaped before exiting.
"""
import ctypes as c
import json
import os
import subprocess
import socket
import struct
import time

if os.geteuid() != 0:
    raise SystemExit("Run in the owner's sudo terminal")
cf = c.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
security = c.CDLL('/System/Library/Frameworks/Security.framework/Security')
ptr = c.c_void_p
cf.CFStringCreateWithBytes.argtypes = [ptr, ptr, c.c_long, c.c_uint32, c.c_ubyte]
cf.CFStringCreateWithBytes.restype = ptr
cf.CFNumberCreate.argtypes = [ptr, c.c_long, ptr]
cf.CFNumberCreate.restype = ptr
cf.CFDataCreate.argtypes = [ptr, ptr, c.c_long]
cf.CFDataCreate.restype = ptr
cf.CFDictionaryCreate.argtypes = [ptr, ptr, ptr, c.c_long, ptr, ptr]
cf.CFDictionaryCreate.restype = ptr
cf.CFRelease.argtypes = [ptr]
cf.CFURLGetFileSystemRepresentation.argtypes = [ptr, c.c_ubyte, ptr, c.c_long]
cf.CFURLGetFileSystemRepresentation.restype = c.c_ubyte
security.SecCodeCopyGuestWithAttributes.argtypes = [ptr, ptr, c.c_uint32, c.POINTER(ptr)]
security.SecRequirementCreateWithString.argtypes = [ptr, c.c_uint32, c.POINTER(ptr)]
security.SecCodeCheckValidity.argtypes = [ptr, c.c_uint32, ptr]
security.SecCodeCopyStaticCode.argtypes = [ptr, c.c_uint32, c.POINTER(ptr)]
security.SecCodeCopyPath.argtypes = [ptr, c.c_uint32, c.POINTER(ptr)]
parent, inherited = socket.socketpair()
child = subprocess.Popen(['/usr/local/lib/keyvalet/bin/kv-cli', 'relay', 'recover', 'r3a-probe-unused-account', '--json'],
                         stdin=inherited, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
inherited.close()
owned = []
try:
    time.sleep(.15)
    if child.poll() is not None:
        print(json.dumps({'child_exit_before_probe': child.returncode, 'ui_requests': 0}))
    else:
        pid = c.c_int(child.pid)
        number = cf.CFNumberCreate(None, 3, c.byref(pid)); owned.append(number)
        token = parent.getsockopt(0, 0x006, 32)
        token_pid = struct.unpack('8I', token)[5]
        audit = cf.CFDataCreate(None, token, len(token)); owned.append(audit)
        keys = (ptr*1)(ptr.in_dll(security, 'kSecGuestAttributeAudit').value)
        values = (ptr*1)(audit)
        attributes = cf.CFDictionaryCreate(None, keys, values, 1,
            c.addressof(c.c_byte.in_dll(cf, 'kCFTypeDictionaryKeyCallBacks')),
            c.addressof(c.c_byte.in_dll(cf, 'kCFTypeDictionaryValueCallBacks')))
        owned.append(attributes)
        code = ptr()
        guest = security.SecCodeCopyGuestWithAttributes(None, attributes, 0, c.byref(code))
        owned.append(code)
        text = b'identifier "dev.keyvalet.cli" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
        string = cf.CFStringCreateWithBytes(None, text, len(text), 0x08000100, 0); owned.append(string)
        requirement = ptr()
        parsed = security.SecRequirementCreateWithString(string, 0, c.byref(requirement)); owned.append(requirement)
        validity = security.SecCodeCheckValidity(code, 0, requirement) if guest == 0 and parsed == 0 else None
        static = ptr()
        copied = security.SecCodeCopyStaticCode(code, 0, c.byref(static)) if guest == 0 else None
        owned.append(static)
        url = ptr()
        path_status = security.SecCodeCopyPath(static, 0, c.byref(url)) if copied == 0 else None
        owned.append(url)
        buffer = c.create_string_buffer(4096)
        path = buffer.value.decode() if path_status == 0 and cf.CFURLGetFileSystemRepresentation(url, 1, buffer, len(buffer)) else None
        print(json.dumps({'ui_requests': 0, 'relay_requests': 0, 'guest_status': guest,
                          'audit_peer_matches_spawned_cli': token_pid == child.pid,
                          'requirement_parse_status': parsed, 'validity_status': validity,
                          'code_path': path, 'expected_path': '/usr/local/lib/keyvalet/bin/kv-cli'}))
finally:
    for ref in reversed(owned):
        if ref:
            cf.CFRelease(ref)
    if child.poll() is None:
        child.terminate()
    child.communicate(timeout=5)
    parent.close()
