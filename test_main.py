"""Isolated correctness tests; these are not real network measurements."""
import socket
import struct
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import main


def message(kind, code, identifier, sequence, payload=b"Tarun"):
    header = struct.pack("!BBHHH", kind, code, 0, identifier, sequence)
    packet = header + payload
    return struct.pack("!BBH", kind, code, main.checksum(packet)) + packet[4:]


class PacketTests(unittest.TestCase):
    def test_known_checksum_and_odd_length(self):
        self.assertEqual(main.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        self.assertEqual(main.checksum(b"a"), 0x9EFF)

    def test_request_is_valid_echo(self):
        request = main.build_request(42, 3, b"Tarun")
        self.assertEqual(struct.unpack("!BBHHH", request[:8])[::3], (8, 42))
        self.assertEqual(main.checksum(request), 0)

    def test_reply_matches_all_fields(self):
        reply = message(0, 0, 42, 3)
        self.assertTrue(main.matches_reply(reply, 42, 3, b"Tarun"))
        for packet in [reply[:7], reply[:-1], message(0, 0, 43, 3),
                       message(0, 0, 42, 4), message(8, 0, 42, 3),
                       message(0, 1, 42, 3), message(0, 0, 42, 3, b"other")]:
            self.assertFalse(main.matches_reply(packet, 42, 3, b"Tarun"))

    def test_error_queue_requires_matching_request_and_icmp_origin(self):
        request = main.build_request(42, 3, b"Tarun")
        error = struct.pack("=IBBBBII", 113, 2, 3, 1, 0, 0, 0)
        offender = struct.pack("=H", socket.AF_INET) + b"\0\0" + socket.inet_aton("10.0.0.1") + bytes(8)
        ancillary = [(socket.SOL_IP, 11, error + offender)]
        result = main.decode_error(request[:8], ancillary, request)
        self.assertEqual(result, (3, 1, "10.0.0.1"))
        self.assertIsNone(main.decode_error(main.build_request(42, 4, b"Tarun"), ancillary, request))
        self.assertIsNone(main.decode_error(request, [(socket.SOL_IP, 11, error[:10])], request))
        local = struct.pack("=IBBBBII", 113, 1, 3, 1, 0, 0, 0)
        self.assertIsNone(main.decode_error(request, [(socket.SOL_IP, 11, local)], request))

    def test_time_exceeded_and_unknown_codes_are_visible(self):
        self.assertIn("TTL", main.error_description(11, 0))
        self.assertIn("Host", main.error_description(3, 1))
        self.assertIn("code 99", main.error_description(3, 99))


class SummaryTests(unittest.TestCase):
    def test_packet_loss_and_reply_only_rtt(self):
        results = [dict(status="REPLY", sent=True, rtt=float(i), detail="") for i in range(1, 9)]
        results += [dict(status="TIMEOUT", sent=True, rtt=None, detail="")]*2
        result = main.summarize("127.0.0.1", results)
        self.assertEqual((result['sent'], result['received'], result['loss']), (10, 8, 20))
        self.assertEqual((result['minimum'], result['maximum'], result['average']), (1, 8, 4.5))
        self.assertEqual(result['status'], 'REACHABLE')

    def test_no_reply_and_no_send_are_distinct(self):
        timeout = main.summarize('127.0.0.1', [dict(status='TIMEOUT', sent=True, rtt=None, detail='')])
        self.assertEqual(timeout['loss'], 100)
        self.assertIsNone(timeout['average'])
        local = main.summarize('127.0.0.1', [dict(status='LOCAL ERROR', sent=False, rtt=None, detail='Permission denied')])
        self.assertIsNone(local['loss'])
        self.assertEqual(local['status'], 'LOCAL ERROR')

    def test_mixed_errors_preserve_diagnostics(self):
        results = [dict(status='ICMP ERROR', sent=True, rtt=None, detail='Host unreachable'),
                   dict(status='TIMEOUT', sent=True, rtt=None, detail='No reply')]
        summary = main.summarize('127.0.0.1', results)
        self.assertEqual(summary['status'], 'ICMP ERROR')
        self.assertEqual(summary['results'], results)


class InputAndExecutionTests(unittest.TestCase):
    def test_inputs_and_duplicates(self):
        self.assertEqual(main.validate_inputs('127.0.0.1, 127.0.0.1, 1.1.1.1', '3', '0.5'),
                         (['127.0.0.1', '1.1.1.1'], 3, 0.5))
        for targets, count, timeout in [('bad', 3, 1), ('::1', 3, 1), ('', 3, 1),
                                       ('127.0.0.1', 0, 1), ('127.0.0.1', 21, 1),
                                       ('127.0.0.1', 2, 'nan'), ('127.0.0.1', 2, 'inf'),
                                       ('127.0.0.1', 2, 0)]:
            with self.assertRaises(ValueError):
                main.validate_inputs(targets, count, timeout)

    def test_non_device_addresses_are_rejected(self):
        for target in ['0.0.0.0', '224.0.0.1', '255.255.255.255']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                main.validate_inputs(target, '2', '1')

    def test_interrupt_signals_workers_before_executor_shutdown(self):
        stop = threading.Event()
        pool = MagicMock()
        pool.__enter__.return_value = pool
        pool.submit.return_value.result.side_effect = KeyboardInterrupt()
        with patch.object(main, 'ThreadPoolExecutor', return_value=pool):
            with self.assertRaises(KeyboardInterrupt):
                main.check_targets(['127.0.0.1'], 20, 10, stop_event=stop)
        self.assertTrue(stop.is_set())

    def test_cli_interrupt_exits_cleanly(self):
        with patch.object(main.sys, 'argv', ['main.py', '--cli']), \
             patch.object(main, 'check_targets', side_effect=KeyboardInterrupt()):
            with self.assertRaises(SystemExit) as context:
                try:
                    main.main()
                except KeyboardInterrupt:
                    self.fail('CLI propagated KeyboardInterrupt instead of exiting cleanly')
        self.assertEqual(context.exception.code, 130)

    def test_permission_error_is_not_timeout(self):
        with patch.object(main.socket, 'socket', side_effect=PermissionError('Permission denied')):
            result = main.probe_once('127.0.0.1', 1, 0.1)
        self.assertEqual(result['status'], 'LOCAL ERROR')
        self.assertFalse(result['sent'])

    def test_local_receive_error_is_not_remote_timeout(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ('0.0.0.0', 42)
        sock.recvmsg.side_effect = BlockingIOError()
        sock.recvfrom.side_effect = OSError(113, 'Local receive failure without ICMP evidence')
        with patch.object(main.socket, 'socket', return_value=sock), \
             patch.object(main.select, 'select', return_value=([sock], [], [])):
            result = main.probe_once('127.0.0.1', 1, 0.1)
        self.assertEqual(result['status'], 'LOCAL ERROR')
        self.assertTrue(result['sent'])
        sock.__exit__.assert_called_once()

    def test_unrelated_traffic_does_not_reset_deadline(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ('0.0.0.0', 42)
        sock.recvmsg.side_effect = BlockingIOError()
        sock.recvfrom.return_value = (b'unrelated', ('127.0.0.2', 0))
        with patch.object(main.socket, 'socket', return_value=sock), \
             patch.object(main.select, 'select', return_value=([sock], [], [])), \
             patch.object(main.time, 'monotonic', side_effect=[0, 0.01, 0.02, 0.11]):
            result = main.probe_once('127.0.0.1', 1, 0.1)
        self.assertEqual(result['status'], 'TIMEOUT')
        sock.sendto.assert_called_once()
        sock.__exit__.assert_called_once()

    def test_failed_send_is_not_counted(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ('0.0.0.0', 42)
        sock.sendto.side_effect = OSError(101, 'Network unavailable')
        with patch.object(main.socket, 'socket', return_value=sock):
            result = main.probe_once('127.0.0.1', 1, 0.1)
        self.assertEqual(result['status'], 'LOCAL ERROR')
        self.assertFalse(result['sent'])

    def test_concurrent_results_keep_input_order(self):
        def check(target, count, timeout, ttl, stop_event):
            return {'target': target}
        with patch.object(main, 'check_target', side_effect=check):
            self.assertEqual(main.check_targets(['127.0.0.1', '127.0.0.2'], 2, 1),
                             [{'target': '127.0.0.1'}, {'target': '127.0.0.2'}])

    def test_cancelled_check_does_not_send(self):
        stop = threading.Event()
        stop.set()
        with patch.object(main.socket, 'socket') as create_socket:
            result = main.probe_once('127.0.0.1', 1, 10, stop_event=stop)
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertFalse(result['sent'])
        create_socket.assert_not_called()

    def test_close_signal_stops_a_waiting_probe(self):
        stop = threading.Event()
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ('0.0.0.0', 42)
        sock.recvmsg.side_effect = BlockingIOError()
        def wait(*args):
            stop.set()
            return [], [], []
        with patch.object(main.socket, 'socket', return_value=sock), \
             patch.object(main.select, 'select', side_effect=wait):
            result = main.probe_once('127.0.0.1', 1, 10, stop_event=stop)
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertTrue(result['sent'])
        sock.__exit__.assert_called_once()

    def test_cancelled_targets_skip_remaining_probes(self):
        stop = threading.Event()
        stop.set()
        started = time.monotonic()
        with patch.object(main, 'probe_once') as probe:
            results = main.check_targets(['127.0.0.1'] * 16, 20, 10, stop_event=stop)
        self.assertLess(time.monotonic() - started, 1)
        self.assertTrue(all(s['status'] == 'CANCELLED' for s in results))
        probe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
