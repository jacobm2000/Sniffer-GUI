from scapy.all import *
import tkinter as tk
from tkinter import filedialog,ttk,scrolledtext
import threading
import time
import matplotlib.pyplot as plt
from sniffer_core import( packet_callback, set_output_callback,get_packets,
packets_clear, init_protocol_count,get_protocol_count,set_sniffing_status_callback)
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

sniffing=False

#sets up the callback function for checking if sniffing
def is_sniffing():
    return sniffing
set_sniffing_status_callback(is_sniffing)


#This function0 temporarly allows the output area to be writen to and then disables it after to prevent user tampering
def append_output(text):
    output_area.config(state='normal')
    output_area.insert(tk.END, f'{text}')
    output_area.config(state='disabled')
    output_area.see(tk.END)
    
set_output_callback(append_output)
        
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
                return
                
        except:
             tk.messagebox.showinfo("Error", "Only Integer values can be inputted into the port number field")
             sniffing=False
             append_output("Error sniffing Stopped\n")
             return
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
    packets=get_packets()
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
    packets_clear()
    output_area.config(state='normal')
    output_area.delete('1.0', tk.END)
    output_area.config(state='disabled')
    port_field.delete(0, tk.END)
    time_field.delete(0, tk.END)
    timed_check_var.set(0)
    init_protocol_count()

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
    
def show_pie_chart():
    do_stop()
    protocol_counts=get_protocol_count()
    labels = []
    sizes = []
    for key, value in protocol_counts.items():
        if value > 0:
            labels.append(key)
            sizes.append(value)

    if not sizes:
        tk.messagebox.showinfo("No Data", "No packets captured yet.")
        return

    # Create a new window
    chart_window = tk.Toplevel(root)
    chart_window.title("Protocol Distribution Pie Chart")
    chart_window.geometry("600x400")  # Adjust window size as needed

    fig, ax = plt.subplots(figsize=(5, 4))  # Adjust figure size

    # Create pie chart
    wedges, _ = ax.pie(sizes, startangle=90)

    total = sum(sizes)
    legend_labels = [f"{label}: {size} ({size / total:.1%})" for label, size in zip(labels, sizes)]
    ax.legend(wedges, legend_labels, title="Protocols", loc="center left", bbox_to_anchor=(1, 0.5))

    ax.axis('equal')
    fig.tight_layout()  # Automatically adjust layout to fit legend

    canvas = FigureCanvasTkAgg(fig, master=chart_window)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)


    
    
# Create the main window
root = tk.Tk()
root.title("Sniffer-GUI")
root.geometry("700x750")

# Create a frame to hold label and input for port number
port_frame = tk.Frame(root)
port_frame.pack(pady=20)


port_label = ttk.Label(port_frame, text="Enter port number")
port_label.pack(side=tk.LEFT)


port_field = ttk.Entry(port_frame, width=30)
port_field.pack(side=tk.LEFT, padx=5)

# Create a frame to hold label,input, and button for timed start
timed_frame = ttk.Frame(root)
timed_frame.pack(pady=20)


timed_label = ttk.Label(timed_frame, text="Enter time in seconds")
timed_label.pack(side=tk.LEFT)


time_field = ttk.Entry(timed_frame, width=30)
time_field.pack(side=tk.LEFT, padx=5)

# Variable to hold the state of the checkbox (0 = unchecked, 1 = checked)
timed_check_var = tk.IntVar()

# Create the checkbox
timed_check = ttk.Checkbutton(timed_frame, text="Enable Timed Capture", variable=timed_check_var)
timed_check.pack(side=tk.LEFT,padx=5)


#Frame for Action buttons such as run, stop ,and clear
actions_frame = tk.Frame(root)
actions_frame.pack(pady=5)
# Create a buttons
run_button = ttk.Button(actions_frame, text="Start Sniffing", command=check_mode)
run_button.pack(side=tk.LEFT,padx=5)

stop_button = ttk.Button(actions_frame, text="Stop Sniffing", command=do_stop)
stop_button.pack(side=tk.LEFT,padx=5)
                 
clear_button = ttk.Button(actions_frame, text="Clear", command=do_clear)
clear_button.pack(side=tk.LEFT,padx=5)



# Create a text area for output
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
output_area.pack(fill=tk.Y, expand=True, padx=10, pady=10)

bottom_frame = tk.Frame(root)
bottom_frame.pack(pady=20)
chart_button = ttk.Button(bottom_frame, text="Show Protocol Pie Chart", command=show_pie_chart)
chart_button.pack(side=tk.LEFT,padx=5)

save_button = ttk.Button(bottom_frame, text="Save to PCAP", command=do_save)
save_button.pack(side=tk.LEFT,padx=5)

# Start the GUI event loop
root.mainloop()