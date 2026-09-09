import csv
import json
import subprocess
import tempfile

import pandas as pd

EXTRACTION_VERSION = 'transport-dns-quic-v2'
CONTRACT = 'tshark-tcp-stream-wire-bytes-v1'
FIELDS = ['frame.number', 'frame.time_epoch', 'frame.len', 'tcp.stream',
          'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport',
          'tcp.flags.syn', 'tcp.flags.ack', 'udp.stream', 'udp.srcport', 'udp.dstport',
          'frame.protocols', 'dns.qry.name', 'dns.flags.response', 'dns.flags.rcode',
          'tls.handshake.extensions_server_name', 'quic.version']


def extract_flows(path, limits, display_filter=None):
    """First-observed direction; original wire lengths include link headers and retransmissions."""
    command = ['tshark', '-n', '-r', str(path), '-c', str(limits['max_packets'] + 1),
               '-o', 'tcp.relative_sequence_numbers:FALSE', '-T', 'fields',
               '-E', 'separator=\t', '-E', 'occurrence=f']
    if display_filter:
        command += ['-Y', display_filter]
    for field in FIELDS:
        command += ['-e', field]
    flows = {}
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as output, tempfile.TemporaryFile(mode='w+') as errors:
        try:
            result = subprocess.run(command, stdout=output, stderr=errors,
                                    timeout=limits['timeout_seconds'], check=False)
        except FileNotFoundError as error:
            raise ValueError('PCAP extraction requires TShark on the application host') from error
        except subprocess.TimeoutExpired as error:
            raise ValueError('Capture extraction exceeded its time limit; split the capture') from error
        if result.returncode:
            raise ValueError('TShark could not decode the entire capture; no partial results were accepted')
        output.seek(0)
        for values in csv.reader(output, delimiter='\t', quoting=csv.QUOTE_NONE):
            (number, time, length, stream, src4, src6, dst4, dst6, sport, dport, syn, ack,
             udp_stream, udp_sport, udp_dport, protocols, query, response, rcode, sni, quic_version) = values
            transport = 'tcp' if stream else 'udp'
            stream, sport, dport = (stream, sport, dport) if stream else (udp_stream, udp_sport, udp_dport)
            if int(number) > limits['max_packets']:
                raise ValueError('Capture exceeds the packet limit; split the capture')
            src, dst = src4 or src6, dst4 or dst6
            if not stream or not src or not dst or not sport or not dport:
                continue
            timestamp, size = float(time), int(length)
            key = (transport, stream)
            if key not in flows:
                if len(flows) >= limits['max_flows']:
                    raise ValueError('Capture exceeds the flow limit; split the capture')
                flows[key] = dict(stream_id=stream, src_ip=src, dst_ip=dst, src_port=int(sport),
                                     dst_port=int(dport), protocol=transport, transport=transport, timestamp=timestamp,
                                     end_timestamp=timestamp, duration=0.0, packets=0, src_packets=0,
                                     dst_packets=0, src_bytes=0, dst_bytes=0, first_packet=int(number),
                                     last_packet=int(number), initial_syn=syn in ('True', '1') and ack in ('False', '0'),
                                     feature_contract=CONTRACT if transport == 'tcp' else 'tshark-udp-stream-wire-bytes-v1',
                                     dns_queries=0, dns_nxdomain=0, dns_requests=[], server_name='', quic_version='')
            flow = flows[key]
            if 'quic' in protocols.split(':'):
                flow['protocol'] = 'quic'
            if sni and not flow['server_name']:
                flow['server_name'] = sni
            if quic_version:
                flow['quic_version'] = quic_version
            if query and response in ('False', '0'):
                flow['dns_queries'] += 1
                flow['dns_requests'].append([timestamp, src, dst, query.lower()])
            if rcode == '3':
                flow['dns_nxdomain'] += 1
            direction = 'src' if (src, int(sport)) == (flow['src_ip'], flow['src_port']) else 'dst'
            flow[direction + '_packets'] += 1
            flow[direction + '_bytes'] += size
            flow['packets'] += 1
            flow['end_timestamp'] = max(flow['end_timestamp'], timestamp)
            flow['timestamp'] = min(flow['timestamp'], timestamp)
            flow['duration'] = flow['end_timestamp'] - flow['timestamp']
            flow['last_packet'] = int(number)
    if not flows:
        raise ValueError('No IPv4/IPv6 TCP or UDP streams found')
    for flow in flows.values():
        flow['dns_requests'] = json.dumps(flow['dns_requests'])
    return pd.DataFrame(flows.values())
