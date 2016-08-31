"""pcap reassembler

Provides a way to reassemble application layer messages from UDP or TCP
packets found in a pcap file.

"""

import sys
import pcap
import struct
import time

# OSI layer constants
PHYSICAL_LAYER      = 1
DATA_LINK_LAYER     = 2
NETWORK_LAYER       = 3
TRANSPORT_LAYER     = 4
SESSION_LAYER       = 5
PRESENTATION_LAYER  = 6
APPLICATION_LAYER   = 7

# TPID from IEEE 802.1Q
_tpid = '\x81\x00'

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

FILL_BYTE = "\x00"

class Message(dict):
    """Reassembled message class

    Message attributes are accessible as regular object attributes using
    dot-notation. The common available attributes are:

     * number       - the message number based on the order of the
                      first fragment
     * fragment_tss - the fragment timestamps
     * ts           - the message timestamp based on the timestamp of
                      the first fragment
     * data         - the raw byte data of the entire message
     * payload      - the raw byte data of the message payload

    """
    @property
    def ts(self):
        return self.fragment_tss[0]

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__

class PcapReassembler:
    def __init__(self):
        # TCP stream buffer
        self._tcp_stream     = None
        # message buffer
        self._msgs           = None
        # packet count
        self._count          = 1
        # OSI layer
        self._layer          = 4
        # strict TCP reassembly policy
        self._strict_policy  = False

    def load_pcap(self, filename, layer=TRANSPORT_LAYER, strict=False):
        """Loads a pcap file and returns a list of Message objects
        containing the reassembled messages for the specified OSI
        layer.

        Usage:
            >>> import pcap_reassembler
            >>> reassembler = pcap_reassembler.PcapReassembler()
            >>> msgs = reassembler.load_pcap('http.cap')
            >>> msgs[0].payload
            'GET /download.html ...'

        """
        if not DATA_LINK_LAYER <= layer <= TRANSPORT_LAYER:
            raise ValueError("Specified OSI layer is not supported.")
        self._tcp_stream    = {}
        self._msgs          = []
        self._count         = 1
        self._layer         = layer
        self._strict_policy = strict
        p = pcap.pcapObject()
        p.open_offline(filename)
        # process all packets
        try:
            p.dispatch(-1, self._process_eth)
        except Exception as e:
            print e

        # flush all TCP connections for remaining messages
        for socks in self._tcp_stream:
            self._tcp_flush(socks)
        self._msgs.sort(key=lambda x: x.number)
        return self._msgs

    def _process_eth(self, length, data, ts):
        """Processes an Ethernet packet (header to checksum; not the full frame).

        May propagate processing to the correct IP version processing function.

        """
        dst_addr = data[0:6]
        src_addr = data[6:12]
        ieee_8021q = data[12:14] == _tpid
        if ieee_8021q:
            tci = data[14:16]
            eth_type = data[16:18]
            pld = data[18:]
        else:
            eth_type = data[12:14]
            pld = data[14:]
        if self._layer > 2:
            if eth_type == _ether_type['IPv4']:
                self._process_ipv4(ts, pld)
            else:
                pass
        else:
            msg = Message({
                'number':           self._count,
                'fragment_tss':     [ts],
                'data':             ''.join(data),
                'src_addr':         src_addr,
                'dst_addr':         dst_addr,
                'eth_type':         eth_type,
                'payload':          ''.join(pld),
            })
            if ieee_8021q:
                msg['tci'] = tci
            self._msgs.append(msg)
        self._count += 1

    def _process_ipv4(self, ts, data):
        """Processes an IPv4 packet.

        Extracts source address, destination address and protocol fields
        and may propagate processing to the correct protocol processing
        function.

        """
        header_len = 4 * (_decode_byte(data[0]) & 0x0f)
        tot_len = _decode_short(data[2:4])
        ip_type = data[9]
        src = data[12:16]
        dst = data[16:20]
        pld = data[header_len:tot_len]
        if self._layer > 3:
            if ip_type == _ip_protocol['TCP']:
                self._process_tcp(ts, src, dst, pld)
            elif ip_type == _ip_protocol['UDP']:
                self._process_udp(ts, src, dst, pld)
            else:
                pass
        else:
            msg = Message({
                'number':           self._count,
                'fragment_tss':     [ts],
                'data':             ''.join(data[:tot_len]),
                'ip_type':          ip_type,
                'src_addr':         src,
                'dst_addr':         dst,
                'payload':          ''.join(pld),
            })
            self._msgs.append(msg)

    def _process_tcp(self, ts, src_addr, dst_addr, data):
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
        src_socket  = (src_addr, src_port)
        dst_socket  = (dst_addr, dst_port)
        sockets     = (src_socket, dst_socket)
        if pld:
            if not sockets in self._tcp_stream:
                self._tcp_stream[sockets] = Message({
                    'number':           self._count,
                    'fragment_tss':     [],
                    'data':             [],
                    'ip_proto':         'TCP',
                    'src_addr':         src_addr,
                    'dst_addr':         dst_addr,
                    'src_port':         src_port,
                    'dst_port':         dst_port,
                    'seq':              seq,
                    'ack':              ack,
                    'payload':          [],
                })
            msg = self._tcp_stream[sockets]
            msg.fragment_tss.append(ts)
            msg.data.append(''.join(data))
            offset = seq - msg.seq
            if offset > len(msg.payload):
                msg.payload.extend(FILL_BYTE * (offset - len(msg.payload)))
            msg.payload[offset:offset+len(pld)] = list(pld)
        if self._strict_policy:
            # Check the other stream in the connection
            sockets = sockets[::-1]
            if (sockets in self._tcp_stream and ack == self._tcp_stream[sockets].seq +
                    len(self._tcp_stream[sockets].payload)):
                self._tcp_flush(sockets)
                del self._tcp_stream[sockets]
        else:
            if sockets in self._tcp_stream and ack != self._tcp_stream[sockets].ack:
                self._tcp_flush(sockets)
                del self._tcp_stream[sockets]

    def _tcp_flush(self, sockets):
        """Flushes the specified TCP connection buffer.

        Adds the flushed message to the message buffer.

        """
        msg = self._tcp_stream[sockets]
        msg.payload = ''.join(msg.payload)
        self._msgs.append(msg)

    def _process_udp(self, ts, src_addr, dst_addr, data):
        """Processes an UDP packet.

        Extracts source and destination port and creates a message
        from the current packet which is added to the message buffer.

        """
        src_port = _decode_short(data[0:2])
        dst_port = _decode_short(data[2:4])
        msg = Message({
            'number':           self._count,
            'fragment_tss':     [ts],
            'data':             ''.join(data),
            'ip_proto':         'UDP',
            'src_addr':         src_addr,
            'dst_addr':         dst_addr,
            'src_port':         src_port,
            'dst_port':         dst_port,
            'payload':          ''.join(data[8:]),
        })
        self._msgs.append(msg)

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
    assert len(b) == 4
    b = map(lambda x: str(_decode_byte(x)), b)
    return '.'.join(b)
