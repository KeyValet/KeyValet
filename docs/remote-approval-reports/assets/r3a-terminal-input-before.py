"""The original cue did not suspend the SSH process sharing Terminal stdin."""
from contextlib import contextmanager

@contextmanager
def pause_agent_input(agent):
    yield
