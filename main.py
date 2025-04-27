from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
import threading
sniffing=False
packets=[]
def packet_callback(pkt):
        packets.append(pkt)
        if not sniffing:
           return
       
        if ARP in pkt:
                  output_area.insert(tk.END,f"[ARP] {pkt[ARP].psrc} -> {pkt[ARP].pdst}")
        elif IP in pkt:
            
            if ICMP in pkt:
                  output_area.insert(tk.END,f"[ICMP] {pkt[IP].src} -> {pkt[IP].dst} Type: {pkt[ICMP].type}")
            elif TCP in pkt:
                    
                  output_area.insert(tk.END,f"[TCP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
            elif UDP in pkt:
                  output_area.insert(tk.END,f"[UDP] {pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}")
            # DNS packets may not always contain a 'qd' field; check is required to avoid exceptions
            if DNS in pkt and pkt[DNS].qd is not None:
                  output_area.insert(tk.END,f"[DNS] {pkt[IP].src} -> {pkt[IP].dst} : {pkt[DNS].qd.qname.decode()}")
        output_area.see(tk.END)
def start_sniff():
    port=str(port_field.get())
    if(port!=""):
         sniff(prn=packet_callback,filter=f'tcp port {port} or udp port {port}', store=False,stop_filter=stop_filter)
    else:
         sniff(prn=packet_callback, store=False,stop_filter=stop_filter)

def do_start():
    global sniffing
    sniffing = True
    output_area.insert(tk.END, "Starting live sniffing...\n")
    sniff_thread = threading.Thread(target=start_sniff)
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_filter(pkt):
    return not sniffing  # If sniffing is False, stop sniffing

def do_stop():
    global sniffing
    sniffing = False
    output_area.insert(tk.END, "\nStopping sniffing...\n")




# Create the main window
root = tk.Tk()
root.title("Sniffer-GUI")
root.geometry("500x500")

# Create a frame to hold label and input for port number
port_frame = tk.Frame(root)
port_frame.pack(pady=20)

# Label
port_label = tk.Label(port_frame, text="Enter port number")
port_label.pack(side=tk.LEFT)

# Entry
port_field = tk.Entry(port_frame, width=30)
port_field.pack(side=tk.LEFT, padx=5)

# Create a buttons
run_button = tk.Button(root, text="Start Sniffing", command=do_start)
run_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Sniffing", command=do_stop)
stop_button.pack(pady=5)

# Create a text area for output
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=100)
output_area.pack(padx=10, pady=10)

# Start the GUI event loop
root.mainloop()