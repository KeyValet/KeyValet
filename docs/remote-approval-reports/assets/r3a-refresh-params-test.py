#!/usr/bin/env python3
"""CI caller-contract regression: reject unsupported template args before fake auth."""
import importlib.util
from pathlib import Path
import unittest


def arguments():
    spec = importlib.util.spec_from_file_location('params', Path(__file__).with_name('r3a-refresh-params.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.proxy_set_arguments('synthetic-not-a-credential')


class CallerContract(unittest.TestCase):
    def test_template_reaches_fake_authorization_without_invalid_attributes(self):
        repo = Path(__file__).resolve().parents[3]
        source = (repo/'rust/crates/kv-mcp/src/tools/http.rs').read_text()
        self.assertIn('if a.value_file.is_some() || a.attributes.is_some()', source)
        params = arguments()
        # The installed frontend rejects this form before contacting the helper.
        rejected = params.get('template') is not None and (
            params.get('value_file') is not None or params.get('attributes') is not None)
        fake_helper_requests = [] if rejected else ['unlock', 'confirm_overwrite', 'set']
        self.assertEqual(fake_helper_requests, ['unlock', 'confirm_overwrite', 'set'])

    def test_correction_retains_proxy_only_and_exact_host(self):
        params = arguments()
        self.assertEqual(params['allowed_hosts'], ['graph.microsoft.com'])
        self.assertIs(params['proxy_only'], True)
        self.assertEqual(params['template'], 'bearer')

    def test_overwrite_still_requires_the_real_helpers_confirmation(self):
        params = arguments()
        self.assertIs(params['overwrite'], True)
        self.assertEqual(params['name'], 'r3a-graph-readonly')
        self.assertEqual(params['type'], 'api_key')


if __name__ == '__main__':
    unittest.main()
