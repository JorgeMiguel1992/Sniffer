import socket 
import struct
import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohl(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data=ethernet_frame(raw_data)
        print('\n Ethernet Frame')
        print('\n Desti', dest_mac)
        print('\n Source',src_mac)
        print('\n Protocol',eth_proto)

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\n IP')
            print('\n Version', version)
            print('\n Header Lenth',header_length)
            print('\n TTL',ttl)
            print('\n Protocol',proto)
            print('\n Source', src)
            print('\n Target',target)
            if proto==1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\n ICMP')
                print('\n Type', icmp_type)
                print('\n Code', code)
                print('\n Checksum', checksum)
            elif proto ==6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data)=tcp_segment(data)
                print('\n TCP')
                print('\n Source Port', src_port)
                print('\n Destination Port', dest_port)
                print('\n Sequence', sequence)
                print('\n Acknowledgment', acknowledgement)
                print('\n URG', flag_urg)
                print('\n ACK', flag_ack)
                print('\n PSH', flag_psh)
                print('\n RST', flag_rst)
                print('\n SYN', flag_syn)
                print('\n FIN', flag_fin)
            elif proto==17:
                src_port, dest_port, length, data=udp_segment(data)
                print('\n UDP')
                print('\n Source Port', src_port)
                print('\n Destination Port', dest_port)
                print('\n Length', length)
            else:
                print('')
            
        else:
            print('')

            

def ethernet_frame(data):
    dest_mac, src_mac, proto= struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto),data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version= version_header_length >> 4
    header_length=   (version_header_length & 15) *4
    ttl,proto,src,target=struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))

def icmp_packet(data):
    icmp_type, code,checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags)=struct.unpack('! H H L L H', data[:14])
    offset=(offset_reserved_flags >> 12)*4
    flag_urg=(offset_reserved_flags & 32)>>5
    flag_ack=(offset_reserved_flags & 16)>>4
    flag_psh=(offset_reserved_flags & 8)>>3
    flag_rst=(offset_reserved_flags & 4)>>2
    flag_syn=(offset_reserved_flags & 2)>>1

    flag_fin=offset_reserved_flags & 1
    return  src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

main()    