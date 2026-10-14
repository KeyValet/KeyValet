"""End the SSH input reader before a cue; the caller registers a fresh agent next."""
from contextlib import contextmanager
from subprocess import TimeoutExpired

@contextmanager
def pause_agent_input(agent):
    if agent is not None and agent.poll() is None:
        agent.terminate()
        try:
            agent.wait(timeout=5)
        except TimeoutExpired:
            agent.kill();agent.wait(timeout=5)
    yield
