#!/usr/bin/env python3
"""Native MCP parameters; validity metadata belongs in the public receipt."""
def proxy_set_arguments(token):
    return {
        'type': 'api_key', 'name': 'r3a-graph-readonly', 'template': 'bearer',
        'value': token, 'allowed_hosts': ['graph.microsoft.com'], 'proxy_only': True,
        'verify': False, 'overwrite': True,
        'description': 'R3-A owner-selected Graph token; acceptance only uses read-only GET',
        'purpose': 'R3-A: update the same host-restricted Graph proxy with the newly authorized short-lived token',
    }
