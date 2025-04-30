from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
import threading
from tkinter import filedialog
import time
sniffing=False
packets=[]

#This function0 temporarly allows the output area to be writen to and then disables it after to prevent user tampering
def append_output(text):
    output_area.config(state='normal')
    output_area.insert(tk.END, f'{text}')
    output_area.config(state='disabled')
    output_area.see(tk.END)
    
def packet_callback(pkt):
        packets.append(pkt)
        if not sniffing:
           return
       
        if ARP in pkt:
                   append_output(f"[ARP] {pkt[ARP].psrc} -> {pkt[ARP].pdst}\n")
        elif IP in pkt:
            
            if ICMP in pkt:
                  append_output(f"[ICMP] {pkt[IP].src} -> {pkt[IP].dst} Type: {pkt[ICMP].type}\n")
            elif TCP in pkt:
                    
                  append_output(f"[TCP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}\n")
            elif UDP in pkt:
                  append_output(f"[UDP] {pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}\n")
            # DNS packets may not always contain a 'qd' field; check is required to avoid exceptions
            if DNS in pkt and pkt[DNS].qd is not None:
                  append_output(f"[DNS] {pkt[IP].src} -> {pkt[IP].dst} : {pkt[DNS].qd.qname.decode()}\n")
        
def start_sniff():
    #if the port input field is empty dont check for int as this means the users does not wish to select a port
    global sniffing
    port=""
    if(str(port_field.get())!=''):
        port=str(port_field.get())
    #checks to make sure the user inputted an inteter and if not a warning will be displayed
        try:
            int(port)
            if(int(port)<1 or int(port)>65535):
                tk.messagebox.showinfo("Error", "Port number must be a value 1-65535")
                sniffing=False
                append_output("Error sniffing Stopped\n")
                
        except:
             tk.messagebox.showinfo("Error", "Only Integer values can be inputted into the port number field")
             sniffing=False
             append_output("Error sniffing Stopped\n")
    if(port!=""):
         sniff(prn=packet_callback,filter=f'tcp port {port} or udp port {port}', store=False,stop_filter=stop_filter)
    else:
         sniff(prn=packet_callback, store=False,stop_filter=stop_filter)

def do_start():
    global sniffing
    sniffing = True
    append_output("Starting live sniffing...\n")
    sniff_thread = threading.Thread(target=start_sniff)
    sniff_thread.daemon = True
    sniff_thread.start()

#this function will be called when the user hits start to see if they selected timed sniff or not
def check_mode():
    
    if (timed_check_var.get()==1):
        timed_sniff()
    else:
        do_start()
def stop_filter(pkt):
    return not sniffing  # If sniffing is False, stop sniffing

def do_stop():
    global sniffing
    #checks to see if sniffing is true so the user can't use the stop button when the program is not sniffing
    if sniffing==True:
        sniffing = False
        append_output("\nStopping sniffing...\n")

def do_save():
    #checks to see if there is packets to save and if not output a message telling the user
    if packets:
        filename = tk.filedialog.asksaveasfilename(defaultextension=".pcap",
                                                 filetypes=[("PCAP files", "*.pcap")])
        if filename:
            wrpcap(filename, packets)
            append_output(f"\nSaved {len(packets)} packets to {filename}\n")
    else:
         append_output("\nNo packets to save!\n")
       
def do_clear():
    do_stop()
    packets.clear()
    output_area.config(state='normal')
    output_area.delete('1.0', tk.END)
    output_area.config(state='disabled')
    port_field.delete(0, tk.END)
    time_field.delete(0, tk.END)
    timed_check_var.set(0)
   

def timed_sniff():
    def run():
        try:
           t=int(time_field.get())
           if(t<=0):
             tk.messagebox.showinfo("Error", "Only values greater than zero can be inputted into the time field")
             return
        except:
            tk.messagebox.showinfo("Error", "Only Integer values can be inputted into the time field")
            return
        do_start()
        append_output(f"\nSniffing for {t} seconds\n")
        time.sleep(t) 
        append_output(f"\n{t} seconds have elapsed")
        do_stop()
    # This thread is used so the main thread is not frozen and the GUI interface still displays
    threading.Thread(target=run, daemon=True).start()
    
# Create the main window
root = tk.Tk()
root.title("Sniffer-GUI")
root.geometry("700x700")

# Create a frame to hold label and input for port number
port_frame = tk.Frame(root)
port_frame.pack(pady=20)


port_label = tk.Label(port_frame, text="Enter port number")
port_label.pack(side=tk.LEFT)


port_field = tk.Entry(port_frame, width=30)
port_field.pack(side=tk.LEFT, padx=5)

# Create a frame to hold label,input, and button for timed start
timed_frame = tk.Frame(root)
timed_frame.pack(pady=20)


timed_label = tk.Label(timed_frame, text="Enter time in seconds")
timed_label.pack(side=tk.LEFT)


time_field = tk.Entry(timed_frame, width=30)
time_field.pack(side=tk.LEFT, padx=5)

# Variable to hold the state of the checkbox (0 = unchecked, 1 = checked)
timed_check_var = tk.IntVar()

# Create the checkbox
timed_check = tk.Checkbutton(timed_frame, text="Enable Timed Capture", variable=timed_check_var)
timed_check.pack(side=tk.LEFT,padx=5)

# Create a buttons
run_button = tk.Button(root, text="Start Sniffing", command=check_mode)
run_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Sniffing", command=do_stop)
stop_button.pack(pady=5)
                 
clear_button = tk.Button(root, text="Clear", command=do_clear)
clear_button.pack(pady=5)


# Create a text area for output
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=75, height=25,state='disabled')
output_area.pack(padx=10, pady=10)

save_button = tk.Button(root, text="Save to PCAP", command=do_save)
save_button.pack(pady=5)
# Start the GUI event loop
root.mainloop()