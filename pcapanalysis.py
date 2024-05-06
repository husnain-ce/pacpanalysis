import pyshark
import hashlib

class MITMException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class MITMProject(object):
    def __init__(self):
        self.cap = pyshark.FileCapture('TCP.reflection_fall2023.pcap')
        self.class_id = "CS60353257"

        # TODO: Change this to YOUR Georgia Tech ID!!!
        # This is your 9-digit Georgia Tech ID
        self.student_id = '900000000'

    def get_student_hash(self, value):
        return hashlib.sha256((self.student_id + self.class_id + value).encode('UTF-8')).hexdigest()

    def count_syn_ack_packets(self):
        syn_ack_count = 0

        for packet in self.cap:
            if 'TCP' in packet and int(packet.tcp.flags_syn) == 1 and int(packet.tcp.flags_ack) == 1:
                syn_ack_count += 1
                print(f"Counting SYN+ACK Packet: {syn_ack_count}")

        return syn_ack_count

    def count_rst_packets(self):
        rst_count = 0

        for packet in self.cap:
            if 'TCP' in packet and self._is_rst_packet(packet):
                rst_count += 1
                print(f"Counting RST Packet: {rst_count}")

        return rst_count

    def find_victim_ip_port(self):
        ip_counts = {}
        port_counts = {}

        for packet in self.cap:
            if 'TCP' in packet and int(packet.tcp.flags_syn) == 1 and int(packet.tcp.flags_ack) == 1:
                dest_ip = str(packet.ip.dst)
                src_port = str(packet.tcp.srcport)

                ip_counts[dest_ip] = ip_counts.get(dest_ip, 0) + 1
                port_counts[src_port] = port_counts.get(src_port, 0) + 1

        most_targeted_ip = max(ip_counts, key=ip_counts.get)
        most_used_port = max(port_counts, key=port_counts.get)

        return most_targeted_ip, int(most_used_port)

    def _is_rst_packet(self, packet):
        return 'TCP' in packet and int(packet.tcp.flags_syn) == 0 and int(packet.tcp.flags_ack) == 0 and int(packet.tcp.flags_fin) == 0 and int(packet.tcp.flags_reset) == 1

if __name__ == '__main__':
    pcap_analysis = MITMProject()
    ip, port = pcap_analysis.find_victim_ip_port()
    synack = pcap_analysis.count_syn_ack_packets()
    rst = pcap_analysis.count_rst_packets()
    print("IP and Port: ", ip, port)
    print("Number of SYN+ACK Packets : ", synack)
    print("Number of RST Packets : ", rst)
