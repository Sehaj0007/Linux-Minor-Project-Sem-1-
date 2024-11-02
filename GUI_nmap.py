#!/usr/bin/python3

import nmap
import tkinter as tk
from tkinter import messagebox


def run_scan():
    ip_addr = ip_entry.get()
    scan_type = scan_var.get()

    if not ip_addr:
        messagebox.showerror("Input Error", "Please enter a valid IP address.")
        return

    if scan_type not in resp_dict:
        messagebox.showerror("Input Error", "Please select a valid scan type.")
        return

    try:
        scanner = nmap.PortScanner()
        print(f"Scanning {ip_addr} with {scan_type}...")  # Debugging output
        nmap_version = scanner.nmap_version()  # Get nmap version
        scanner.scan(ip_addr, "1-1024", resp_dict[scan_type][0])

        if scanner[ip_addr].state() == 'up':
            output = f"nmap Version: {nmap_version}\n"
            output += f"Scanner Status: {scanner[ip_addr].state()}\n"
            #output += f"Protocols: {scanner[ip_addr].all_protocols()}\n"
            for protocol in scanner[ip_addr].all_protocols():
                open_ports = scanner[ip_addr][protocol].keys()
                output += f"Open Ports for {protocol}: {list(open_ports)}\n"
        else:
            output = "The host is down or unreachable."

        messagebox.showinfo("Scan Results", output)
    except Exception as e:
        messagebox.showerror("Scan Error", f"An error occurred: {e}")
        print(f"Error: {e}")  # Debugging output


# Create the main window
root = tk.Tk()
root.title("Nmap Automation Tool")

# Define scan types
resp_dict = {
    'SYN ACK Scan': ['-v -sS', 'tcp'],
    'UDP Scan': ['-v -sU', 'udp'],
    'Comprehensive Scan': ['-v -sS -sV -sC -A -O', 'tcp']
}

# Create UI elements
tk.Label(root, text="Welcome to the Nmap Automation Tool").pack(pady=10)
tk.Label(root, text="Please Enter the IP Address:").pack()
ip_entry = tk.Entry(root)
ip_entry.pack(pady=5)

tk.Label(root, text="Select the Type of Scan:").pack()
scan_var = tk.StringVar(value='SYN ACK Scan')
for scan_type in resp_dict.keys():
    tk.Radiobutton(root, text=scan_type, variable=scan_var, value=scan_type).pack(anchor='w')

tk.Button(root, text="Run Scan", command=run_scan).pack(pady=20)

# Start the Tkinter main loop
root.mainloop()
