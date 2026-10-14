#!/usr/bin/env python3
"""Installed MCP transport for owner-attended acceptance; never log wire contents."""
import json
import queue
import subprocess
import threading
import time


class McpFailure(Exception):
    """Messages are fixed diagnostic codes, never tool output."""


class Client:
    def __init__(self, command, env=None):
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env,
        )
        self.frames = queue.Queue()
        self.notifications = []
        self.next_id = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(1024 * 1024 + 1)
                if not line:
                    self.frames.put(None)
                    return
                if len(line) > 1024 * 1024:
                    self.frames.put(None)
                    return
                try:
                    frame = json.loads(line)
                except ValueError:
                    self.frames.put(None)
                    return
                self.frames.put(frame)
        except (OSError, ValueError):
            self.frames.put(None)

    def send(self, frame):
        try:
            self.process.stdin.write(json.dumps(frame).encode() + b'\n')
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise McpFailure('mcp_write_failed') from None

    def request(self, method, params, timeout=180):
        self.next_id += 1
        request_id = self.next_id
        self.send({'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpFailure('mcp_response_timeout')
            try:
                frame = self.frames.get(timeout=remaining)
            except queue.Empty:
                raise McpFailure('mcp_response_timeout') from None
            if frame is None:
                raise McpFailure('mcp_closed')
            if frame.get('id') == request_id:
                if 'error' in frame:
                    raise McpFailure('mcp_rpc_rejected')
                return frame.get('result', {})
            # Keep only safe identifiers and counts, never arbitrary notification text.
            params = frame.get('params', {})
            self.notifications.append({
                'method': frame.get('method'),
                'received_monotonic': time.monotonic(),
                'approval_id': params.get('approval_id'),
                'pid': params.get('pid'),
            })

    def initialize(self, name='r3a-installed-acceptance'):
        result = self.request('initialize', {
            'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': name, 'version': '1'},
        }, timeout=15)
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        return result

    def tool(self, name, arguments=None, timeout=180):
        return self.request('tools/call', {
            'name': name, 'arguments': arguments or {},
        }, timeout=timeout)

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def payload(result):
    """Decode native ok_data without ever forwarding its raw text to the transcript."""
    if result.get('isError'):
        raise McpFailure('mcp_tool_rejected')
    structured = result.get('structuredContent')
    if isinstance(structured, dict):
        return structured
    decoder = json.JSONDecoder()
    for content in result.get('content', []):
        if content.get('type') != 'text':
            continue
        text = content.get('text', '')
        for pos, character in enumerate(text):
            if character != '{':
                continue
            try:
                value, _ = decoder.raw_decode(text[pos:])
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    raise McpFailure('mcp_missing_structured_result')
