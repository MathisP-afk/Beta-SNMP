import sys
import os
import unittest

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, '../RECEIVER'))

from snmp_collector_unified import (
    _ber_read_tlv, _ber_parse_children, _ber_to_int, _ber_to_oid,
    _ber_value_to_str, parse_v2c_raw, parse_snmpv3_raw,
    _password_to_key_sha, PDU_TYPE_TAGS, OID_LIBRARY,
    IPTracker, SNMPPacketQueue, UnifiedSNMPCollector,
)


class TestBERParser(unittest.TestCase):

    def test_read_tlv_integer(self):
        tag, value, nxt = _ber_read_tlv(bytes([0x02, 0x01, 0x03]), 0)
        self.assertEqual(tag, 0x02)
        self.assertEqual(value, b'\x03')

    def test_read_tlv_long_length(self):
        data = bytes([0x04, 0x81, 0x80]) + b'\x00' * 128
        tag, value, _ = _ber_read_tlv(data, 0)
        self.assertEqual(len(value), 128)

    def test_read_tlv_empty_returns_none(self):
        self.assertIsNone(_ber_read_tlv(b'', 0))
        self.assertIsNone(_ber_read_tlv(bytes([0x02]), 0))

    def test_parse_children(self):
        inner = bytes([0x02, 0x01, 0x05, 0x02, 0x01, 0x0A])
        children = _ber_parse_children(inner)
        self.assertEqual(len(children), 2)
        self.assertEqual(_ber_to_int(children[0][1]), 5)
        self.assertEqual(_ber_to_int(children[1][1]), 10)

    def test_ber_to_int(self):
        self.assertEqual(_ber_to_int(b''), 0)
        self.assertEqual(_ber_to_int(b'\x7f'), 127)
        self.assertEqual(_ber_to_int(b'\xff'), -1)
        self.assertEqual(_ber_to_int(b'\x01\x00'), 256)

    def test_ber_to_oid(self):
        self.assertEqual(_ber_to_oid(bytes([43, 6, 1, 2, 1])), '1.3.6.1.2.1')
        self.assertEqual(_ber_to_oid(bytes([43, 6, 1, 2, 1, 1, 1, 0])),
                         '1.3.6.1.2.1.1.1.0')
        self.assertEqual(_ber_to_oid(b''), '')

    def test_value_to_str(self):
        self.assertEqual(_ber_value_to_str(0x02, b'\x2a'), '42')
        self.assertEqual(_ber_value_to_str(0x04, b'hello'), 'hello')
        self.assertEqual(_ber_value_to_str(0x05, b''), '')
        self.assertEqual(_ber_value_to_str(0x40, b'\xc0\xa8\x01\x01'),
                         'c0a80101')


class TestParseV2cRaw(unittest.TestCase):

    def _build_v2c_get(self, community=b'public'):
        oid_b = bytes([43, 6, 1, 2, 1, 1, 1, 0])
        oid_tlv = bytes([0x06, len(oid_b)]) + oid_b
        vb = bytes([0x30, len(oid_tlv) + 2]) + oid_tlv + bytes([0x05, 0x00])
        vbl = bytes([0x30, len(vb)]) + vb
        rid = bytes([0x02, 0x01, 0x01])
        es = bytes([0x02, 0x01, 0x00])
        ei = bytes([0x02, 0x01, 0x00])
        pdu_c = rid + es + ei + vbl
        pdu = bytes([0xA0, len(pdu_c)]) + pdu_c
        ver = bytes([0x02, 0x01, 0x01])
        com = bytes([0x04, len(community)]) + community
        body = ver + com + pdu
        return bytes([0x30, len(body)]) + body

    def test_valid_get(self):
        r = parse_v2c_raw(self._build_v2c_get())
        self.assertIsNotNone(r)
        self.assertEqual(r['community'], 'public')
        self.assertEqual(r['type_pdu'], 'GetRequest')
        self.assertEqual(r['varbinds'][0]['oid'], '1.3.6.1.2.1.1.1.0')

    def test_custom_community(self):
        r = parse_v2c_raw(self._build_v2c_get(b'private'))
        self.assertEqual(r['community'], 'private')

    def test_rejects_bad_input(self):
        self.assertIsNone(parse_v2c_raw(b''))
        self.assertIsNone(parse_v2c_raw(b'\x00\x01\x02'))
        self.assertIsNone(parse_v2c_raw(bytes([0x02, 0x01, 0x01])))


class TestParseSnmpv3(unittest.TestCase):

    def test_rejects_bad_input(self):
        self.assertIsNone(parse_snmpv3_raw(b''))
        self.assertIsNone(parse_snmpv3_raw(b'\x00\x01'))

    def test_rejects_v2c(self):
        raw = bytes([0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x00, 0x04, 0x00])
        self.assertIsNone(parse_snmpv3_raw(raw))


class TestPasswordToKey(unittest.TestCase):

    def test_deterministic_and_length(self):
        eid = bytes.fromhex('80004fb8054d534917e0c200')
        k1 = _password_to_key_sha('test', eid)
        k2 = _password_to_key_sha('test', eid)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 20)

    def test_different_inputs(self):
        eid = b'\x01\x02\x03'
        self.assertNotEqual(_password_to_key_sha('a', eid),
                            _password_to_key_sha('b', eid))


class TestIPTracker(unittest.TestCase):

    def test_record_and_stats(self):
        t = IPTracker()
        t.record_packet('10.0.0.1', community='public',
                        oids=['1.3.6.1.2.1.1.1.0'])
        s = t.get_stats('10.0.0.1')
        self.assertEqual(s['req_count'], 1)
        self.assertEqual(s['community_count'], 1)

    def test_auth_failure(self):
        t = IPTracker()
        for _ in range(5):
            t.record_auth_failure('10.0.0.1')
        self.assertEqual(t.get_stats('10.0.0.1')['auth_failure_count'], 5)

    def test_unknown_ip(self):
        s = IPTracker().get_stats('192.168.0.1')
        self.assertEqual(s['req_count'], 0)


class TestSNMPPacketQueue(unittest.TestCase):

    def test_put_get(self):
        q = SNMPPacketQueue(max_size=10)
        q.put_packet({'x': 1})
        self.assertEqual(q.get_packet(timeout=0.1), {'x': 1})

    def test_empty_returns_none(self):
        self.assertIsNone(SNMPPacketQueue().get_packet(timeout=0.1))

    def test_full_no_crash(self):
        q = SNMPPacketQueue(max_size=2)
        q.put_packet({'a': 1})
        q.put_packet({'b': 2})
        q.put_packet({'c': 3})
        self.assertEqual(q.size(), 2)


class TestCollectorLogic(unittest.TestCase):

    def setUp(self):
        os.environ.setdefault('SNMP_API_URL', 'http://localhost:8000')
        os.environ.setdefault('SNMP_API_KEY', 'k')
        self.c = UnifiedSNMPCollector(
            api_endpoint='http://localhost:8000', api_key='k', verbose=False)

    def test_oid_exact(self):
        self.assertEqual(self.c.get_oid_info('1.3.6.1.2.1.1.1.0')[0], 'sysDescr')

    def test_oid_prefix(self):
        self.assertEqual(self.c.get_oid_info('1.3.6.1.2.1.2.2.1.10.5')[0],
                         'ifInOctets')

    def test_oid_unknown(self):
        self.assertEqual(self.c.get_oid_info('1.3.6.1.99')[0], 'Unknown_OID')

    def test_severite_normal(self):
        niv, _ = self.c.analyser_severite(
            {'type_pdu': 'Response', 'contenu': {'varbinds': []}})
        self.assertEqual(niv, 'NORMAL')

    def test_severite_set_elevated(self):
        niv, _ = self.c.analyser_severite(
            {'type_pdu': 'SetRequest', 'contenu': {'varbinds': []}})
        self.assertIn(niv, ['ELEVEE', 'CRITIQUE'])

    def test_severite_auth_failure(self):
        niv, _ = self.c.analyser_severite(
            {'type_pdu': 'Trap',
             'contenu': {'varbinds': [], 'trap_type': 'AUTH_FAILURE'}})
        self.assertIn(niv, ['ELEVEE', 'CRITIQUE'])

    def test_severite_unknown_community(self):
        niv, raisons = self.c.analyser_severite(
            {'type_pdu': 'GetRequest', 'community': 'hack',
             'contenu': {'varbinds': []}}, src_ip='10.0.0.99')
        self.assertNotEqual(niv, 'NORMAL')


class TestConstants(unittest.TestCase):

    def test_pdu_tags(self):
        self.assertEqual(set(PDU_TYPE_TAGS.keys()), {0, 1, 2, 3, 5, 6, 7, 8})

    def test_oid_library(self):
        self.assertGreater(len(OID_LIBRARY), 20)
        for oid in OID_LIBRARY:
            self.assertTrue(oid.startswith('1.3.'))


if __name__ == '__main__':
    unittest.main()
