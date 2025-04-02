from scapy.all import sniff, IP, TCP
from collections import defaultdict


class TrafficAnalyzer:
    
    def __init__(self):
        self.connections -defaultdict(list)
        self.flow_stats = defaultdict(lambda:{
            "packets_count":0,
            "bytes_count":0,
            "start_time":None,
            "last_time":None
        })
        
    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst 
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            
            flow_key = (ip_src, ip_dst, port_src, port_dst)
            
            stats = self.flow_stats[flow_key]
            stats["packets_count"] += 1
            stats["bytes_count"] += len(packet)
            current_time = packet.time
            
            if not stats["start_time"]:
                stats["start_time"] = current_time
            stats["last_time"] = current_time
            
        return self.extract_features(packet, stats)
    
    def extract_features(self, packet, stats):
        return {
            'packet_size': len(packet),
            'flow_duration': stats["last_time"] - stats["start_time"],
            'packet_rate': stats["packets_count"] / (stats["last_time"] - stats["start_time"]),
            'byte_rate': stats["bytes_count"] / (stats["last_time"] - stats["start_time"]),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window,
        }