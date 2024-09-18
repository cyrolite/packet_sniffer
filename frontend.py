import tkinter as tk
from tkinter import scrolledtext
import threading
from sniffer_tools import sniff_packets, format_multi_line_data

captured_packets = []  # Global variable to store sniffed packets
is_sniffing = False

def start_sniffing():
    global is_sniffing
    is_sniffing = True
    threading.Thread(target=sniff_packets, args=(captured_packets,), daemon=True).start()

def stop_sniffing():
    global is_sniffing
    is_sniffing = False

def create_ui():
    root = tk.Tk()
    root.title("Packet Sniffer")

    # Start/Stop Buttons
    start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
    start_button.pack(pady=5)

    stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing)
    stop_button.pack(pady=5)

    # Text area to display captured packets
    text_area = scrolledtext.ScrolledText(root, width=80, height=20)
    text_area.pack(pady=10)

    def update_ui():
        text_area.delete('1.0', tk.END)  # Clear the text area
        for packet in captured_packets[-10:]:  # Show the last 10 packets
            text_area.insert(tk.END, format_multi_line_data('', packet) + '\n')
        root.after(1000, update_ui)  # Refresh every second

    update_ui()  # Start the UI update loop
    root.mainloop()

if __name__ == "__main__":
    create_ui()

