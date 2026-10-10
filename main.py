"""ICMP network checks. Run without arguments to start the local website."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import math
import os
import select
import socket
import struct
import sys
import threading
import time

# Linux IP_RECVERR exposes actual ICMP type/code through the error queue.
IP_RECVERR = 11


def checksum(data):
    """Internet checksum: one's complement of the 16-bit word sum."""
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def build_request(identifier, sequence, payload):
    packet = struct.pack('!BBHHH', 8, 0, 0, identifier, sequence) + payload
    return struct.pack('!BBH', 8, 0, checksum(packet)) + packet[4:]


def matches_reply(packet, identifier, sequence, payload):
    if len(packet) < 8 or checksum(packet) != 0:
        return False
    kind, code, _, reply_id, reply_seq = struct.unpack('!BBHHH', packet[:8])
    return (kind == 0 and code == 0 and reply_id == identifier
            and reply_seq == sequence and packet[8:] == payload)


def decode_error(quoted, ancillary, request):
    """Match a Linux extended ICMP error to the request on this socket."""
    if len(quoted) < 8 or quoted[:2] != b'\x08\x00' or quoted[4:8] != request[4:8]:
        return None
    for level, kind, data in ancillary:
        if level != socket.SOL_IP or kind != IP_RECVERR or len(data) < 16:
            continue
        _, origin, icmp_type, code, _, _, _ = struct.unpack('=IBBBBII', data[:16])
        if origin != 2 or icmp_type not in (3, 11):
            continue
        sender = 'unknown'
        if len(data) >= 24 and struct.unpack('=H', data[16:18])[0] == socket.AF_INET:
            sender = socket.inet_ntoa(data[20:24])
        return icmp_type, code, sender
    return None


def error_description(kind, code):
    if kind == 3:
        descriptions = {0: 'Network unreachable', 1: 'Host unreachable',
                        2: 'Protocol unreachable', 3: 'Port unreachable',
                        4: 'Fragmentation needed', 5: 'Source route failed',
                        9: 'Network administratively prohibited',
                        10: 'Host administratively prohibited',
                        13: 'Communication administratively prohibited'}
        return descriptions.get(code, f'Destination unreachable, code {code}')
    return {0: 'TTL exceeded in transit', 1: 'Reassembly time exceeded'}.get(
        code, f'Time exceeded, code {code}')


def probe_once(target, sequence, timeout, ttl=64, stop_event=None):
    sent = False
    if stop_event is not None and stop_event.is_set():
        return dict(status='CANCELLED', sent=False, rtt=None, detail='Check stopped')
    if not sys.platform.startswith('linux'):
        return dict(status='LOCAL ERROR', sent=False, rtt=None,
                    detail='This project uses Linux ICMP sockets.')
    try:
        # A separate socket per probe isolates identifiers and old errors.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as sock:
            sock.bind(('', 0))
            identifier = sock.getsockname()[1]
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
            sock.setblocking(False)
            payload = b'Tarun-CN-' + os.urandom(16)
            request = build_request(identifier, sequence, payload)
            started = time.monotonic()
            sock.sendto(request, (target, 0))
            sent = True
            deadline = started + timeout
            while time.monotonic() < deadline:
                if stop_event is not None and stop_event.is_set():
                    return dict(status='CANCELLED', sent=True, rtt=None, detail='Check stopped')
                try:
                    quoted, ancillary, _, _ = sock.recvmsg(512, 512, socket.MSG_ERRQUEUE)
                except BlockingIOError:
                    pass
                else:
                    error = decode_error(quoted, ancillary, request)
                    if error:
                        kind, code, sender = error
                        return dict(status='ICMP ERROR', sent=True, rtt=None,
                                    detail=f'{error_description(kind, code)} '
                                           f'(type {kind}, code {code}, from {sender})')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([sock], [], [], min(remaining, 0.05))
                if not ready:
                    continue
                try:
                    packet, address = sock.recvfrom(65535)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    # Only an explicit matching ICMP error is remote evidence.
                    try:
                        quoted, ancillary, _, _ = sock.recvmsg(512, 512, socket.MSG_ERRQUEUE)
                    except BlockingIOError:
                        raise exc
                    error = decode_error(quoted, ancillary, request)
                    if error:
                        kind, code, sender = error
                        return dict(status='ICMP ERROR', sent=True, rtt=None,
                                    detail=f'{error_description(kind, code)} '
                                           f'(type {kind}, code {code}, from {sender})')
                    raise
                if address[0] == target and matches_reply(packet, identifier, sequence, payload):
                    return dict(status='REPLY', sent=True,
                                rtt=(time.monotonic() - started) * 1000,
                                detail=f'Echo Reply from {target}')
        return dict(status='TIMEOUT', sent=True, rtt=None,
                    detail=f'No matching ICMP response within {timeout:g} s')
    except OSError as exc:
        return dict(status='LOCAL ERROR', sent=sent, rtt=None,
                    detail=f'{exc}. Check ICMP socket permissions and network settings.')


def summarize(target, results):
    sent = sum(result['sent'] for result in results)
    rtts = [result['rtt'] for result in results if result['status'] == 'REPLY']
    statuses = {result['status'] for result in results}
    status = ('REACHABLE' if rtts else 'LOCAL ERROR' if 'LOCAL ERROR' in statuses
              else 'CANCELLED' if not results or 'CANCELLED' in statuses
              else 'ICMP ERROR' if 'ICMP ERROR' in statuses else 'TIMEOUT')
    return dict(target=target, status=status, sent=sent, received=len(rtts),
                loss=(sent - len(rtts)) / sent * 100 if sent else None,
                minimum=min(rtts) if rtts else None, maximum=max(rtts) if rtts else None,
                average=sum(rtts) / len(rtts) if rtts else None, results=results)


def check_target(target, count, timeout, ttl=64, stop_event=None):
    results = []
    for sequence in range(1, count + 1):
        if stop_event is not None and stop_event.is_set():
            break
        result = probe_once(target, sequence, timeout, ttl, stop_event)
        results.append(result)
        if result['status'] in ('LOCAL ERROR', 'CANCELLED'):
            break
    return summarize(target, results)


def check_targets(targets, count, timeout, ttl=64, stop_event=None):
    stop_event = stop_event if stop_event is not None else threading.Event()
    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as pool:
        jobs = [pool.submit(check_target, target, count, timeout, ttl, stop_event) for target in targets]
        try:
            return [job.result() for job in jobs]
        except KeyboardInterrupt:
            stop_event.set()
            raise


def validate_inputs(text, count, timeout):
    try:
        targets = list(dict.fromkeys(str(ipaddress.IPv4Address(t.strip())) for t in text.split(',')))
        count, timeout = int(count), float(timeout)
    except (ValueError, TypeError):
        raise ValueError('Enter IPv4 addresses separated by commas and valid numeric settings.') from None
    if any(ipaddress.IPv4Address(t).is_unspecified or ipaddress.IPv4Address(t).is_multicast
           or t == '255.255.255.255' for t in targets):
        raise ValueError('Use device IPv4 addresses, not unspecified, multicast or broadcast addresses.')
    if not 1 <= len(targets) <= 16:
        raise ValueError('Enter between 1 and 16 target addresses.')
    if not 1 <= count <= 20:
        raise ValueError('Packet count must be between 1 and 20.')
    if not math.isfinite(timeout) or not 0.1 <= timeout <= 10:
        raise ValueError('Timeout must be between 0.1 and 10 seconds.')
    return targets, count, timeout


def format_value(value, suffix=''):
    return 'N/A' if value is None else f'{value:.2f}{suffix}'


def print_summary(summary):
    print(f"\nTarget: {summary['target']}    Status: {summary['status']}")
    print(f"Sent: {summary['sent']}    Replies: {summary['received']}    "
          f"Loss: {format_value(summary['loss'], '%')}")
    print('RTT min / avg / max: ' + ' / '.join(
        format_value(summary[key], ' ms') for key in ('minimum', 'average', 'maximum')))
    for number, result in enumerate(summary['results'], 1):
        print(f"  #{number} {result['status']}: {result['detail']}"
              + (f" ({result['rtt']:.2f} ms)" if result['rtt'] is not None else ''))


def main():
    parser = argparse.ArgumentParser(description='ICMP network failure detection with a local browser UI.')
    parser.add_argument('--cli', action='store_true', help='Use terminal output instead of the website')
    parser.add_argument('--targets', default='127.0.0.1', help='Comma-separated IPv4 addresses')
    parser.add_argument('--count', default='5')
    parser.add_argument('--timeout', default='2')
    parser.add_argument('--ttl', type=int, default=64, help='CLI only: IPv4 TTL, 1 to 255')
    args = parser.parse_args()
    if not args.cli:
        from server import serve
        serve()
        return
    try:
        targets, count, timeout = validate_inputs(args.targets, args.count, args.timeout)
        if not 1 <= args.ttl <= 255:
            raise ValueError('TTL must be between 1 and 255.')
    except ValueError as exc:
        parser.error(str(exc))
    try:
        summaries = check_targets(targets, count, timeout, args.ttl)
    except KeyboardInterrupt:
        parser.exit(130, '\nCheck stopped.\n')
    for summary in summaries:
        print_summary(summary)
    print('\nA timeout does not prove the device is down. ICMP may be filtered.')


if __name__ == '__main__':
    main()
