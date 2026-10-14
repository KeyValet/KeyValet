#!/usr/bin/env python3
"""Test the installer's status gate with fake helper output and a fake clock."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

class Clock:
    def __init__(self):self.now=0
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=seconds

class Readiness(unittest.TestCase):
    def gate(self,frames):
        path=Path(__file__).with_name('r3a-install-revocations-ndu.py')
        tree=ast.parse(path.read_text())
        functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='status']
        self.assertEqual(len(functions),1)
        code=compile(ast.Module(body=functions,type_ignores=[]),str(path),'exec')
        clock=Clock();calls=[]
        def run(args,*_):
            calls.append(args)
            frame=frames[min(len(calls)-1,len(frames)-1)]
            return SimpleNamespace(returncode=frame[0],stdout=json.dumps(frame[1]))
        scope={'run':run,'json':json,'time':clock}
        exec(code,scope)
        return scope['status'],calls,clock

    def ready(self):
        return {'ok':True,'result':{'remote':{'device_id':'CI-executor','account_id':'CI-account',
            'mode':'per_use','pending_n':0,'grants_n':0,'unattended':False,'relay':'connected'}}}

    def test_active_service_and_cli_success_do_not_prove_remote_ipc_is_ready(self):
        fallback={'ok':True,'result':{'remote':None,'remote_error':'ipc_unavailable'}}
        gate,calls,clock=self.gate([(0,fallback),(0,self.ready())])
        self.assertEqual(gate()['device_id'],'CI-executor')
        self.assertEqual(len(calls),2)
        self.assertGreater(clock.now,0)

    def test_a_connect_failure_can_recover_without_authentication(self):
        gate,calls,_=self.gate([(5,{'ok':False,'error':{'code':'ipc_unavailable'}}),(0,self.ready())])
        self.assertEqual(gate()['grants_n'],0)
        self.assertEqual(len(calls),2)
        self.assertTrue(all('status' in call and '--json' in call for call in calls))

    def test_an_unavailable_helper_stops_at_a_fixed_deadline(self):
        gate,calls,clock=self.gate([(0,{'ok':True,'result':{'remote':None}})])
        with self.assertRaisesRegex(RuntimeError,'^native_owner_status_unavailable$'):gate()
        self.assertLessEqual(clock.now,15.5)
        self.assertLess(len(calls),60)

if __name__=='__main__':unittest.main()
