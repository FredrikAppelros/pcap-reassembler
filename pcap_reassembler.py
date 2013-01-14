"""pcap reassembler

Provides a way to reassemble application layer messages from UDP or TCP
packets found in a pcap file.

"""

import sys
import pcap
import struct
import time

_ether_type = {
    'IPv4': '\x08\x00',
    'IPv6': '\x86\xdd',
}

_ip_protocol = {
    'TCP': '\x06',
    'UDP': '\x11',
}

_tcp_conn   = None
_msgs       = None

class Message(dict):
    """Reassembled message class

    Message attributes are accessible as regular object attributes using
    dot-notation. The common available attributes are:

     * timestamp
     * ip_protocol
     * source_addr
     * destination_addr
     * source_port
     * destination_port
     * data

    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__

def load_pcap(filename):
    """Loads a pcap file and returns a list of messages"""
    global _tcp_conn, _msgs
    _tcp_conn   = {}
    _msgs       = []
    p = pcap.pcapObject()
    p.open_offline(filename)
    # process all packets
    p.dispatch(-1, _process_eth)
    # flush TCP connections
    for src in _tcp_conn:
        _tcp_flush(src)
    return _msgs

def _process_eth(length, data, ts):
    """Function comment"""
    # strips ethernet header
    eth_type = data[12:14]
    pld = data[14:]
    if eth_type == _ether_type['IPv4']:
        _process_ipv4(ts, pld)
    else:
        raise NotImplementedError

def _process_ipv4(ts, data):
    """Function comment"""
    # extract source address, destination address, protocol type
    header_len = 4 * (_decode_byte(data[0]) & 0x0f)
    tot_len = _decode_short(data[2:4])
    ip_type = data[9]
    src = data[12:16]
    dst = data[16:20]
    pld = data[header_len:tot_len]
    if ip_type == _ip_protocol['TCP']:
        _process_tcp(ts, src, dst, pld)
    elif ip_type == _ip_protocol['UDP']:
        _process_udp(ts, src, dst, pld)
    else:
        raise NotImplementedError

def _process_tcp(ts, src_addr, dst_addr, data):
    """Function comment"""
    # reassemble PDUs by buffering packets and flushing when ack changes
    src_port = _decode_short(data[0:2])
    dst_port = _decode_short(data[2:4])
    seq = _decode_word(data[4:8])
    ack = _decode_word(data[8:12])
    offset = (_decode_byte(data[12]) & 0xf0) >> 4
    pld = data[4*offset:]
    if pld:
        if not src_addr in _tcp_conn:
            _tcp_conn[src_addr] = Message({
                'timestamp':        ts,
                'ip_protocol':      'TCP',
                'source_addr':      src_addr,
                'destination_addr': dst_addr,
                'source_port':      src_port,
                'destination_port': dst_port,
                'seq':              seq,
                'ack':              ack,
                'data':             [],
            })
        offset = seq - _tcp_conn[src_addr].seq
        _tcp_conn[src_addr].data[offset:offset+len(pld)] = list(pld)
    if src_addr in _tcp_conn and ack != _tcp_conn[src_addr].ack:
        _tcp_flush(src_addr)
        del _tcp_conn[src_addr]

def _tcp_flush(src):
        msg = _tcp_conn[src]
        msg['data'] = ''.join(msg.data)
        _msgs.append(msg)

def _process_udp(ts, src_addr, dst_addr, data):
    """Function comment"""
    src_port = _decode_short(data[0:2])
    dst_port = _decode_short(data[2:4])
    msg = Message({
        'timestamp':        ts,
        'ip_protocol':      'UDP',
        'source_addr':      src_addr,
        'destination_addr': dst_addr,
        'source_port':      src_port,
        'destination_port': dst_port,
        'data':             ''.join(data[8:]),
    })
    _msgs.append(msg)

def _decode_byte(data):
    """Function comment"""
    return struct.unpack('!B', data)[0]

def _decode_short(data):
    """Function comment"""
    return struct.unpack('!H', data)[0]

def _decode_word(data):
    """Function comment"""
    return struct.unpack('!I', data)[0]

def validate_tcp_checksum(length, src, dst, data):
    """Function comment"""
    # this is currently unused as we simply insert newer data
    # over old data without checking the checksum
    csum = _decode_short(data[16:18])
    data = list(data)
    data[16:18] = '\x00\x00'
    if len(data) % 2 != 0:
        data.append('\x00')
    sum = 0
    sum += _decode_short(src[0:2])
    sum += _decode_short(src[2:4])
    sum += _decode_short(dst[0:2])
    sum += _decode_short(dst[2:4])
    sum += 0x0006
    sum += length
    for i in range(0, len(data), 2):
        sum += _decode_short(data[i] + data[i+1])
    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)
    return ~sum & 0xffff == csum

def address_to_string(b):
    """Function comment"""
    assert(len(b) == 4)
    b = map(lambda x: str(_decode_byte(x)), b)
    return '.'.join(b)

