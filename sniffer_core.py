from scapy.all import *



protocol_counts = {
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'ARP': 0,
}
#resets protocol counts back to zero
packets=[]
output_callback = None

#This allows the GUI to reset the packets captured with the clear button
def packets_clear():
    packets.clear()
    
# This code sets the callback funtion to the append output function in the GUI    
def set_output_callback(callback):
    global output_callback
    output_callback = callback
# Callback function to get status of sniffing from GUI
def set_sniffing_status_callback(callback):
    global sniffing_status_callback
    sniffing_status_callback = callback


def init_protocol_count():
    global protocol_counts
    protocol_counts= {
        'TCP': 0,
        'UDP': 0,
        'ICMP': 0,
        'ARP': 0,
    }
def get_protocol_count():
    return protocol_counts

def get_packets():
    return packets

def packet_callback(pkt):
    if sniffing_status_callback():
                packets.append(pkt)
               
                if ARP in pkt:
                           output_callback(f"[ARP] {pkt[ARP].psrc} -> {pkt[ARP].pdst}\n")
                           protocol_counts['ARP']+=1
                elif IP in pkt:
                    
                    if ICMP in pkt:
                          protocol_counts['ICMP']+=1
                          output_callback(f"[ICMP] {pkt[IP].src} -> {pkt[IP].dst} Type: {pkt[ICMP].type}\n")
                    elif TCP in pkt:
                          protocol_counts['TCP']+=1
                          output_callback(f"[TCP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}\n")
                    elif UDP in pkt:
                          protocol_counts['UDP']+=1
                          output_callback(f"[UDP] {pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}\n")
                    # DNS packets may not always contain a 'qd' field; check is required to avoid exceptions
                    if DNS in pkt and pkt[DNS].qd is not None:
                          output_callback(f"[DNS] {pkt[IP].src} -> {pkt[IP].dst} : {pkt[DNS].qd.qname.decode()}\n")