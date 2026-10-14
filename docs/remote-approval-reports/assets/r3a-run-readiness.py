#!/usr/bin/env python3
"""Wait for the system pkttyagent notify-fd without starting authentication early."""
import os
import select
import subprocess


def wait_agent_registration(agent, reader, timeout):
    if not select.select([reader], [], [], timeout)[0]:
        raise RuntimeError('polkit_agent_registration_timeout')
    if os.read(reader, 1) != b'':
        raise RuntimeError('polkit_agent_registration_failed')
    # A failing process also closes inherited fds. Successful registration leaves
    # the agent running, so reject an exit rather than treating that EOF as ready.
    try:
        agent.wait(timeout=.05)
    except subprocess.TimeoutExpired:
        return
    raise RuntimeError('polkit_agent_registration_failed')
