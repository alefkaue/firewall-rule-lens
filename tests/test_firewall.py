import copy
from pathlib import Path
import json
import unittest
from firewall_rule_lens import audit

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples'


def policy():
    return json.loads((EXAMPLES / 'risky.json').read_text())


class FirewallTests(unittest.TestCase):
    def test_open_admin_and_opposite_shadow(self):
        report = audit(policy())
        self.assertEqual([f['rule'] for f in report['findings']], ['unrestricted_source_admin', 'shadowed_rule'])
        self.assertEqual(report['findings'][1]['shadowed_by'], 'allow-admin')
        self.assertEqual(report['findings'][1]['severity'], 'high')

    def test_order_and_partial_coverage(self):
        value = policy()
        value['rules'].reverse()
        self.assertNotIn('shadowed_rule', [f['rule'] for f in audit(value)['findings']])
        value = policy()
        value['rules'][1]['ports'] = [22, 23]
        self.assertNotIn('shadowed_rule', [f['rule'] for f in audit(value)['findings']])

    def test_protocol_and_address_families(self):
        value = policy()
        value['rules'][1]['protocol'] = 'udp'
        self.assertNotIn('shadowed_rule', [f['rule'] for f in audit(value)['findings']])
        value['rules'][1].update(source='2001:db8::/32', destination='2001:db8:1::/48')
        self.assertNotIn('shadowed_rule', [f['rule'] for f in audit(value)['findings']])

    def test_any_protocol_and_ipv6(self):
        value = policy()
        value['rules'][0].update(protocol='any', source='::/0', destination='2001:db8::/32', ports=[1, 65535])
        value['rules'][1].update(source='2001:db8:2::/48', destination='2001:db8:1::/48')
        rules = {f['rule'] for f in audit(value)['findings']}
        self.assertEqual(rules, {'shadowed_rule', 'unrestricted_source_admin'})

    def test_clean_and_default_allow(self):
        clean = json.loads((EXAMPLES / 'scoped.json').read_text())
        self.assertEqual(audit(clean)['findings'], [])
        clean['default_action'] = 'allow'
        self.assertEqual(audit(clean)['findings'][0]['rule'], 'default_allow')

    def test_reject_invalid_and_unsupported_fields(self):
        for field, replacement in [('ports', [True, 22]), ('ports', [23, 22]),
                                   ('protocol', 'icmp'), ('source', '192.0.2.1/24'),
                                   ('destination', '::/0'), ('interface', 'eth0')]:
            value = copy.deepcopy(policy())
            value['rules'][0][field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                audit(value)
        value = policy()
        value['rules'][1]['id'] = value['rules'][0]['id']
        with self.assertRaises(ValueError):
            audit(value)
