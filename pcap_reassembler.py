"""pcap reassembler

Provides a way to reassemble application layer messages from UDP or TCP
packets found in a pcap file.

"""

import sys
import pcap
import struct
import time

# EtherType constants
_ether_type = {
    'IPv4': '\x08\x00',
    'IPv6': '\x86\xdd',
}

# IP protocol field constants
_ip_protocol = {
    'TCP': '\x06',
    'UDP': '\x11',
}

# TCP connection buffer
_tcp_conn       = None
# message buffer
_msgs           = None
# packet count
_count           = 1
# strict TCP reassembly policy
_strict_policy   = False

class Message(dict):
    """Reassembled message class

    Message attributes are accessible as regular object attributes using
    dot-notation. The common available attributes are:

     * number
     * timestamp
     * ip_protocol
     * src_addr
     * dst_addr
     * src_port
     * dst_port
     * data

    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__

def load_pcap(filename, strict=False):
    """Loads a pcap file and returns a list of Message objects
    containing the reassembled application layer messages.

    Usage:
        >>> import pcap_reassembler
        >>> msgs = pcap_reassembler.load_pcap('http.cap')
        >>> msgs[0].data
        'GET /download.html ...'

    """
    global _tcp_conn, _msgs, _count, _strict_policy
    _tcp_conn       = {}
    _msgs           = []
    _count          = 1
    _strict_policy  = strict
    p = pcap.pcapObject()
    p.open_offline(filename)
    # process all packets
    p.dispatch(-1, _process_eth)
    # flush all TCP connections for remaining messages
    for src in _tcp_conn:
        _tcp_flush(src)
    _msgs.sort(key=lambda x: x.number)
    return _msgs

def _process_eth(length, data, ts):
    """Processes an Ethernet packet (header to checksum; not the full frame).

    Propagates processing to the correct IP version processing function.

    """
    global _count
    eth_type = data[12:14]
    pld = data[14:]
    if eth_type == _ether_type['IPv4']:
        _process_ipv4(ts, pld)
    else:
        pass
    _count += 1

def _process_ipv4(ts, data):
    """Processes an IPv4 packet.

    Extracts source address, destination address and protocol fields
    and propagates processing to the correct protocol processing
    function.

    """
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
        pass

def _process_tcp(ts, src_addr, dst_addr, data):
    """Processes a TCP packet.

    Extracts source port, destination port, sequence number and
    acknowledgement number and adds the payload to the current message
    data. If there is no current message in the buffer one is created
    with the attributes of the current packet. When the acknowledgement
    number changes the TCP connection buffer associated with the
    current source address is flushed.

    """
    # reassemble PDUs by buffering packets and flushing when ack changes
    src_port = _decode_short(data[0:2])
    dst_port = _decode_short(data[2:4])
    seq = _decode_word(data[4:8])
    ack = _decode_word(data[8:12])
    offset = (_decode_byte(data[12]) & 0xf0) >> 4
    pld = data[4*offset:]
    src_socket = (src_addr, src_port)
    dst_socket = (dst_addr, dst_port)
    if pld:
        if not dst_socket in _tcp_conn:
            _tcp_conn[dst_socket] = Message({
                'number':           _count,
                'timestamp':        ts,
                'ip_protocol':      'TCP',
                'src_addr':         src_addr,
                'dst_addr':         dst_addr,
                'src_port':         src_port,
                'dst_port':         dst_port,
                'seq':              seq,
                'ack':              ack,
                'data':             [],
            })
        offset = seq - _tcp_conn[dst_socket].seq
        _tcp_conn[dst_socket].data[offset:offset+len(pld)] = list(pld)
    if _strict_policy:
        if src_socket in _tcp_conn and ack == _tcp_conn[src_socket].seq + len(_tcp_conn[src_socket].data):
            _tcp_flush(src_socket)
            del _tcp_conn[src_socket]
    else:
        if dst_socket in _tcp_conn and ack != _tcp_conn[dst_socket].ack:
            _tcp_flush(dst_socket)
            del _tcp_conn[dst_socket]

def _tcp_flush(src):
    """Flushes the specified TCP connection buffer.

    Adds the flushed message to the message buffer.

    """
    msg = _tcp_conn[src]
    msg['data'] = ''.join(msg.data)
    _msgs.append(msg)

def _process_udp(ts, src_addr, dst_addr, data):
    """Processes an UDP packet.

    Extracts source and destination port and creates a message
    from the current packet which is added to the message buffer.

    """
    src_port = _decode_short(data[0:2])
    dst_port = _decode_short(data[2:4])
    msg = Message({
        'number':           _count,
        'timestamp':        ts,
        'ip_protocol':      'UDP',
        'src_addr':         src_addr,
        'dst_addr':         dst_addr,
        'src_port':         src_port,
        'dst_port':         dst_port,
        'data':             ''.join(data[8:]),
    })
    _msgs.append(msg)

def _decode_byte(data):
    """Decodes one byte of network data into an unsigned char."""
    return struct.unpack('!B', data)[0]

def _decode_short(data):
    """Decodes two bytes of network data into an unsigned short."""
    return struct.unpack('!H', data)[0]

def _decode_word(data):
    """Decodes four bytes of network data into an unsigned int."""
    return struct.unpack('!I', data)[0]

def validate_tcp_checksum(length, src, dst, data):
    """Validates a TCP checksum according to RFC 1071.

    Takes length, source address and destination address for computing
    the IP pseudo-header. The data parameter contains the entire TCP
    packet.

    """
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
    """Converts an IP address to its string representation.

    Takes a 4-byte string representing an IP address, and returns a
    dot-separated decimal representation on the form '123.123.123.123'.

    """
    assert(len(b) == 4)
    b = map(lambda x: str(_decode_byte(x)), b)
    return '.'.join(b)

