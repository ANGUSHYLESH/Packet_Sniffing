import socket 
import struct
import textwrap

TAB_1 = "\t -  "
TAB_2 = "\t\t -  "
TAB_3 = "\t\t\t -   "
TAB_4 = "\t\t\t\t -   "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "


def main():
	conn = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))
	
	while True:
		raw_data , addr = conn.recvfrom(65536)
		dest_mac , src_mac , eth_proto , data = ethernet_frame(raw_data)
		print("\nEthernet Frame ")
		print(TAB_1 +'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac , src_mac , eth_proto ))
		
		#8 for IPv4
		
		if  eth_proto == 8 :
			(version, header_length , ttl , proto , src , target , data)=ipv4_packet(data)
			print(TAB_1  + 'IPv4 Packets:')
			print(TAB_2 + 'Version : {} , Header Length : {} , TTL : {}'.format(version, header_length , ttl ))
			print(TAB_2 + 'Protocol : {} , Source : {} , Target : {}'.format(proto , src , target ))
			
			if proto == 1 :
				icmp_type , code , checksum , data = icmp_packet(data)
				print(TAB_1  + 'ICMP Packets:')
				print(TAB_2 + "Type : {} , Code : {} , CheckSum : {} ".format(icmp_type , code , checksum ))
				print(TAB_2 + "Data : ")
				print(format_multi_line(DATA_TAB_3 , data))
				
			elif proto == 6 :
				(src_port , dest_port , sequence , acknowledgment , flags_urg , flags_ack , flags_psh , flags_rst ,flags_syn , flags_fin ,data) = tcp_segment(data)
				print(TAB_1  + 'TCP Packets:')
				print(TAB_2 + 'Source Port : {} , Destination Port : {} '.format(src_port , dest_port))
				print(TAB_2 + "Sequence : {} , Acknowledgment : {} ".format(sequence , acknowledgment))
				print(TAB_2 + "Flags:")
				print(TAB_3 + "URG : {} , ACK : {} , PSH : {} , RST : {} ,SYN : {} , FIN : {} ".format(flags_urg , flags_ack , flags_psh , flags_rst ,flags_syn , flags_fin))			
				print(TAB_2 + "Data:")
				print(format_multi_line(DATA_TAB_3 , data))
				
			elif proto == 17 :
				src_port , dest_port , size ,data = udp_segment (data)
				print(TAB_1 + 'UDP SEGMENT')
				print(TAB_2 + "Source Port : {} , Destination Port : {} , Length : {} ".format(src_port , dest_port , size))
				
			else:
				print(TAB_1+ 'Data:')
				print(format_multi_line(DATA_TAB_2 , data))
		
		else :
			print("Data:")
			print(format_multi_line(DATA_TAB_1 , data))


# unpacking the ethernet  
def ethernet_frame(data):
	dest_mac , src_mac , proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac) , get_mac_addr(src_mac) , socket.htons(proto) , data[14:]

	   
# formatting mac address [ AA:BB:CC:DD:EE:FF ]
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()
	 
#unpack IPv4 packet
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4 
	ttl , proto , src ,target = struct.unpack('! 8x B B 2x 4s 4s ', data[:20])
	return  version, header_length ,ttl , proto , ipv4(src) , ipv4(target) , data[header_length:]

# return properly formatted IPv4
def ipv4(addr):
	return '.'.join(map(str,addr))
	#eg : 127.0.0.1

#unpacking ICMP - internet control message protocol 
def icmp_packet(data):
	icmp_type , code , checksum = struct.unpack('! B B H ',data[:4])
	return icmp_type , code , checksum , data[4:]
	


#unpacking TCP - transfer control protocol 
def tcp_segment(data):
	(src_port , dest_port , sequence , acknowledgment , offset_reserved_flags)= struct.unpack('! H H L L H',data[:14])
	offset= (offset_reserved_flags >> 12 ) * 4
	flags_urg = (offset_reserved_flags & 32 ) >> 5
	flags_ack = (offset_reserved_flags & 16 ) >> 4
	flags_psh = (offset_reserved_flags & 8 ) >> 3
	flags_rst = (offset_reserved_flags & 4 ) >> 2
	flags_syn = (offset_reserved_flags & 2 ) >> 1
	flags_fin = offset_reserved_flags & 1
	return src_port , dest_port , sequence , acknowledgment , flags_urg , flags_ack , flags_psh , flags_rst ,flags_syn , flags_fin , data[offset : ]
	

#unpacking UDP - user datagram protocol 	
def udp_segment (data):
	src_port , dest_port , size = struct.unpack('! H H 2x H',data[:8])
	return 	src_port , dest_port , size , data[8:]



#formatting multiline data
def format_multi_line(prefix , string , size=80):
	size -= len(prefix)
	if isinstance(string , bytes ):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string )
		if size % 2:
			size -= 1
	return "\n".join( [prefix + line for line in textwrap.wrap(string,size) ])

			 
main()