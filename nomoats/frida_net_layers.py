# This file is part of AutoLabel <http://athinagroup.eng.uci.edu/projects/autolabel/>.
# Copyright (C) 2019 Anastasia Shuba, University of California, Irvine.
#
# AutoLabel is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 2 of the License only.
#
# AutoLabel is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with AutoLabel.  If not, see <http://www.gnu.org/licenses/>.

IP_HEADER_DEFAULT_LENGTH = 20
TCP_HEADER_DEFAULT_LENGTH = 20

PROTOCOL_TCP = 6

def create_ipv4_header(dst_ip, data_len):
    """Creates a 20-byte IPv4 header
    """
    # Initialize all bytes to zero
    ip_header = bytearray(IP_HEADER_DEFAULT_LENGTH)
    
    # 1st byte: Version 4, IP Header Len = 5: 0b01000101
    ip_header[0] = 0b01000101

    # 2nd byte: Differentiated Services: not used
    # 3rd and 4th Byte is total length
    total_len = IP_HEADER_DEFAULT_LENGTH  + TCP_HEADER_DEFAULT_LENGTH + data_len
    ip_header[2] = total_len >> 8
    ip_header[3] = total_len & 0xff # need mask here since this number is > 255

    # 5th and 6th Byte is Identification for fragmentation: not used
    # 7th and 8th are Flags and Fragment offset: not used
    # 9th is TTL. Set to 20
    ip_header[8] = 20
    
    # 10th is Protocol: TCP = 6
    ip_header[9] = PROTOCOL_TCP

    # 13, 14, 15, 16 are Source IP - not significant for us, so we use a default address
    # 192.168.10.1
    ip_header[12] = 192
    ip_header[13] = 168
    ip_header[14] = 10
    ip_header[15] = 1

    # 17, 18, 19, 20 are Dest IP    
    ip_header[16] = dst_ip[0]
    ip_header[17] = dst_ip[1]
    ip_header[18] = dst_ip[2]
    ip_header[19] = dst_ip[3]

    # 11th and 12th are header check sum - we can leave as 0
    return ip_header
    
def create_tcp_header():
    """Creates a 20-byte TCP header that can later be updated with the correct port number
    """
    tcp_header = bytearray(TCP_HEADER_DEFAULT_LENGTH)
    
    # 1st and 2nd: Source port - can leave as zero
    # 3rd and 4th: Destination port - will be updated later
    # 5-8: Sequence Number - just keep at zero
    # 9-12: ACK Number - keep at zero

    # 13th and 14th: Data Offset, Reserved, ECN, Control Bits
    offset = 0b01010000 # 5-words = 20 bytes = TCP header len = data offset

    # Set control bits - last 6 are: Urg, Ack, Push, Reset, Syn, Fin
    # We just need push and ack:
    pus_mask = 0b00001000
    ack_mask = 0b00010000

    control_bits = 0
    control_bits = pus_mask | control_bits
    control_bits = ack_mask | control_bits

    tcp_header[12] = offset
    tcp_header[13] = control_bits

    # 15th and 16th: Window
    max_window = 65535
    tcp_header[14] = max_window >> 8
    tcp_header[15] = max_window & 0xff

    # 17th and 18th: Checksum - not needed
    # 19th and 20th: Urgent Pointer: Not used
    # 21-24: MSS option - not used
    # 25-28: must be all zeros

    return tcp_header
    
def update_dst_port(tcp_header, dst_port):
    """Fills in the provided header with the provided destination port number
    """
    # 3rd and 4th: Destination port
    tcp_header[2] = (dst_port >> 8) & 0xff
    tcp_header[3] = dst_port & 0xff
