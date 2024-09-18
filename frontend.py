import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import threading
import socket
import os

class PacketSnifferUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Packet Sniffer")
        self.geometry("1000x700")

        self.sniffing_active = False
        self.sniffing_paused = False
        self.packet_number = 0
        self.dark_mode = False

        self.create_widgets()
        self.update_style()

    def create_widgets(self):
        # Create the menu bar
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit)
        file_menu.add_command(label="Save Packet Data", command=self.save_packet_data)

        # Create the toolbar
        toolbar = tk.Frame(self, bg="lightgrey")
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self.start_button = tk.Button(toolbar, text="Play", command=self.start_sniffing, bg="green", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=2, pady=2)

        self.pause_button = tk.Button(toolbar, text="Pause", command=self.pause_sniffing, bg="yellow", fg="black")
        self.pause_button.pack(side=tk.LEFT, padx=2, pady=2)

        self.stop_button = tk.Button(toolbar, text="Stop", command=self.stop_sniffing, bg="red", fg="white")
        self.stop_button.pack(side=tk.LEFT, padx=2, pady=2)

        self.dark_mode_button = tk.Button(toolbar, text="Dark Mode", command=self.toggle_dark_mode)
        self.dark_mode_button.pack(side=tk.RIGHT, padx=2, pady=2)

        # Create the packet list
        self.packet_list = ttk.Treeview(self, columns=("Number", "Source", "Destination", "Protocol"), show='headings')
        self.packet_list.heading("Number", text="No.")
        self.packet_list.heading("Source", text="Source")
        self.packet_list.heading("Destination", text="Destination")
        self.packet_list.heading("Protocol", text="Protocol")
        self.packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Create the packet details display
        self.packet_display = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=20)
        self.packet_display.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Create the status bar
        self.status_bar = tk.Label(self, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # IP and Port Entry
        self.ip_label = tk.Label(self, text="IP Address:")
        self.ip_label.pack(side=tk.LEFT, padx=2, pady=2)
        self.ip_entry = tk.Entry(self)
        self.ip_entry.pack(side=tk.LEFT, padx=2, pady=2)

        self.port_label = tk.Label(self, text="Port:")
        self.port_label.pack(side=tk.LEFT, padx=2, pady=2)
        self.port_entry = tk.Entry(self)
        self.port_entry.pack(side=tk.LEFT, padx=2, pady=2)

    def start_sniffing(self):
        if not self.sniffing_active:
            self.sniffing_active = True
            self.sniffing_paused = False
            self.update_status("Sniffing started...")
            self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffing_active = False
        self.update_status("Sniffing stopped.")

    def pause_sniffing(self):
        self.sniffing_paused = True
        self.update_status("Sniffing paused.")

    def resume_sniffing(self):
        self.sniffing_paused = False
        self.update_status("Sniffing resumed.")

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.update_style()

    def update_style(self):
        style = ttk.Style()
        if self.dark_mode:
            self.config(bg="black")
            style.configure("Treeview",
                            background="grey20",
                            foreground="white",
                            fieldbackground="grey20")
            style.configure("Treeview.Heading",
                            background="grey30",
                            foreground="white")
            self.packet_display.config(bg="grey20", fg="white")
            self.status_bar.config(bg="black", fg="white")
            self.start_button.config(bg="green4", fg="white")
            self.pause_button.config(bg="goldenrod", fg="black")
            self.stop_button.config(bg="darkred", fg="white")
            self.dark_mode_button.config(bg="yellow", fg="black", text="Light Mode")
        else:
            self.config(bg="white")
            style.configure("Treeview",
                            background="white",
                            foreground="black",
                            fieldbackground="white")
            style.configure("Treeview.Heading",
                            background="lightgrey",
                            foreground="black")
            self.packet_display.config(bg="white", fg="black")
            self.status_bar.config(bg="lightgrey", fg="black")
            self.start_button.config(bg="green", fg="white")
            self.pause_button.config(bg="yellow", fg="black")
            self.stop_button.config(bg="red", fg="white")
            self.dark_mode_button.config(bg="lightgrey", fg="black", text="Dark Mode")

    def update_status(self, message):
        self.status_bar.config(text=f"Status: {message}")

    def display_packet(self, packet_number, src, dst, proto, packet_data):
        """Display packet in the list and details view."""
        self.packet_list.insert("", tk.END, values=(packet_number, src, dst, proto))
        self.packet_display.insert(tk.END, f"Packet {packet_number}:\n{packet_data}\n\n")
        self.packet_display.see(tk.END)

    def sniff_packets(self):
        """Function that runs in a background thread to sniff and display packets."""
        ip = self.ip_entry.get() or socket.gethostbyname(socket.gethostname())
        port = int(self.port_entry.get() or 0)
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((ip, port))
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while self.sniffing_active:
            if not self.sniffing_paused:
                try:
                    raw_data, _ = conn.recvfrom(65536)
                    self.packet_number += 1
                    # Process raw_data to extract details (mock data here)
                    # Replace with actual data processing
                    src, dst, proto = '192.168.1.1', '192.168.1.2', 'TCP'
                    packet_data = raw_data.decode(errors='replace')
                    self.display_packet(self.packet_number, src, dst, proto, packet_data)
                except Exception as e:
                    print(f"Error: {e}")

    def save_packet_data(self):
        """Save the packet data to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.packet_display.get("1.0", tk.END))
            self.update_status(f"Packet data saved to {file_path}")

if __name__ == "__main__":
    app = PacketSnifferUI()
    app.mainloop()

