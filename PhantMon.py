import re
import os
import ctypes
import time
from datetime import datetime
from scapy.all import sniff, wrpcap, rdpcap, conf
import tkinter as tk
from tkinter import ttk
from tkinter import font
from tkinter import filedialog
import threading

# Global variable to keep track of the current alert
current_alert = None

def send_desktop_notification(title, message):
    global current_alert
    if current_alert is not None:
        ctypes.windll.user32.MessageBoxW(current_alert, None, None, 0)  # Close the previous alert
    current_alert = ctypes.windll.user32.MessageBoxW(0, message, title, 0x40 | 0x1)  # 0x40 is MB_ICONINFORMATION, 0x1 is MB_OK
    
    # Bring the alert window to the foreground and make it topmost
    hwnd = ctypes.windll.user32.FindWindowW(None, title)
    if hwnd:
        ctypes.windll.user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0003)  # -1 is HWND_TOPMOST, 0x0003 is SWP_NOMOVE | SWP_NOSIZE
        ctypes.windll.user32.SetForegroundWindow(hwnd)

def capture_traffic(output_file, duration, iface="Ethernet"):
    try:
        packets = sniff(filter="src port 7115", timeout=duration, iface=iface)
        wrpcap(output_file, packets)
        print(f"Captured {len(packets)} packets and saved to {output_file}")
    except Exception as e:
        print(f"Error capturing traffic: {e}")

def check_temperatures(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        camtemp_value = "N/A"
        snstemp_value = "N/A"
        packet_count = len(packets)

        for packet in packets:
            packet_data = bytes(packet)
            camtemp_match = re.search(rb'camtemp\s*:\s*(\d+)', packet_data)
            if camtemp_match:
                temp_value = int(camtemp_match.group(1).decode('utf-8'))
                if temp_value != 0:
                    camtemp_value = temp_value  # Update only if not 0

            snstemp_match = re.search(rb'snstemp\s*:\s*(\d+)', packet_data)
            if snstemp_match:
                temp_value = int(snstemp_match.group(1).decode('utf-8'))
                if temp_value != 0:
                    snstemp_value = temp_value  # Update only if not 0

        os.remove(pcap_file)
        return camtemp_value, snstemp_value, packet_count
    except Exception as e:
        print(f"Error checking temperatures: {e}")
        return "N/A", "N/A", 0

class TemperatureMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Phantom Camera Temperature Monitor")
        self.root.geometry("600x820")
        
        # Define fonts
        self.title_font = font.Font(family="Helvetica", size=16, weight="bold")
        self.label_font = font.Font(family="Helvetica", size=12)
        self.entry_font = font.Font(family="Helvetica", size=10)
        
        self.status_label = ttk.Label(root, text="Status: Stopped", font=self.label_font)
        self.status_label.pack(pady=10)
        
        self.camtemp_label = ttk.Label(root, text="Current Camtemp: N/A", font=self.label_font)
        self.camtemp_label.pack(pady=10)
        
        self.snstemp_label = ttk.Label(root, text="Current Snstemp: N/A", font=self.label_font)
        self.snstemp_label.pack(pady=10)
        
        self.last_packet_label = ttk.Label(root, text="Last Packet Read: N/A", font=self.label_font)
        self.last_packet_label.pack(pady=10)
        
        self.max_camtemp_label = ttk.Label(root, text="Max Camtemp: N/A", font=self.label_font)
        self.max_camtemp_label.pack(pady=10)
        
        self.max_snstemp_label = ttk.Label(root, text="Max Snstemp: N/A", font=self.label_font)
        self.max_snstemp_label.pack(pady=10)
        
        self.packet_count_label = ttk.Label(root, text="Packets Read: 0", font=self.label_font)
        self.packet_count_label.pack(pady=10)
        
        self.dir_label = ttk.Label(root, text="Temp PCAP & Log File Directory:", font=self.label_font)
        self.dir_label.pack(pady=10)
        
        self.dir_frame = ttk.Frame(root)
        self.dir_frame.pack(pady=10)
        
        self.dir_entry = ttk.Entry(self.dir_frame, font=self.entry_font, width=40)
        self.dir_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.dir_button = ttk.Button(self.dir_frame, text="Browse", command=self.browse_directory)
        self.dir_button.pack(side=tk.LEFT)
        
        # Set default directory
        self.dir_entry.insert(0, "C:\\pcap")
        
        self.camtemp_threshold_label = ttk.Label(root, text="Camtemp Threshold:", font=self.label_font)
        self.camtemp_threshold_label.pack(pady=10)
        
        self.camtemp_threshold_entry = ttk.Entry(root, font=self.entry_font, width=10)
        self.camtemp_threshold_entry.insert(0, "40")
        self.camtemp_threshold_entry.pack(pady=10)
        
        self.snstemp_threshold_label = ttk.Label(root, text="Snstemp Threshold:", font=self.label_font)
        self.snstemp_threshold_label.pack(pady=10)
        
        self.snstemp_threshold_entry = ttk.Entry(root, font=self.entry_font, width=10)
        self.snstemp_threshold_entry.insert(0, "40")
        self.snstemp_threshold_entry.pack(pady=10)
        
        self.adapter_label = ttk.Label(root, text="Select Network Adapter:", font=self.label_font)
        self.adapter_label.pack(pady=10)
        
        self.adapter_combobox = ttk.Combobox(root, font=self.entry_font, width=50)
        self.adapter_combobox.pack(pady=10)
        self.populate_adapters()
        
        self.start_button = ttk.Button(root, text="Start", command=self.start_monitoring)
        self.start_button.pack(pady=10)
        
        self.stop_button = ttk.Button(root, text="Stop", command=self.stop_monitoring)
        self.stop_button.pack(pady=10)
        
        self.quit_button = ttk.Button(root, text="Quit", command=self.quit)
        self.quit_button.pack(pady=10)
        
        self.countdown_label = ttk.Label(root, text="Next update in: 10s", font=self.label_font)
        self.countdown_label.pack(pady=10)
        
        self.monitoring = False
        self.max_camtemp = ("N/A", "N/A")
        self.max_snstemp = ("N/A", "N/A")
        self.total_packet_count = 0
        self.last_camtemp = "N/A"
        self.last_snstemp = "N/A"
        self.update_id = None
        self.countdown = 10

        self.update_buttons()

    def populate_adapters(self):
        adapters = conf.ifaces
        adapter_names = [iface.description for iface in adapters.values()]
        self.adapter_combobox['values'] = adapter_names
        if adapter_names:
            self.adapter_combobox.current(0)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def get_pcap_file_path(self, filename):
        directory = self.dir_entry.get()
        if not os.path.exists(directory):
            os.makedirs(directory)
        return os.path.join(directory, filename)

    def get_log_file_path(self):
        directory = self.dir_entry.get()
        if not os.path.exists(directory):
            os.makedirs(directory)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        return os.path.join(directory, f'phantom{timestamp}.csv')

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.status_label.config(text="Status: Monitoring")
            self.update_buttons()
            self.countdown = 10
            self.update_countdown()
            self.schedule_capture()

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.status_label.config(text="Status: Stopped")
            self.update_buttons()
            if self.update_id:
                self.root.after_cancel(self.update_id)

    def update_buttons(self):
        if self.monitoring:
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def schedule_capture(self):
        if self.monitoring:
            threading.Thread(target=self.run_monitoring).start()
            self.update_id = self.root.after(10000, self.schedule_capture)  # Schedule next capture in 10 seconds

    def run_monitoring(self):
        iface = self.adapter_combobox.get()
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pcap_file = self.get_pcap_file_path(f'captured_{timestamp}.pcap')
            capture_traffic(pcap_file, duration=10, iface=iface)  # Capture traffic for 10 seconds
            camtemp_value, snstemp_value, packet_count = check_temperatures(pcap_file)
            
            # Update total packet count
            self.total_packet_count += packet_count
            
            # Update GUI elements
            self.root.after(0, self.update_gui, camtemp_value, snstemp_value, self.total_packet_count)
            
            # Save log file
            self.save_log(camtemp_value, snstemp_value, packet_count)
        except Exception as e:
            print(f"Error in monitoring: {e}")
            
    def update_gui(self, camtemp_value, snstemp_value, total_packet_count):
        if camtemp_value != "N/A":
            self.camtemp_label.config(text=f"Current Camtemp: {camtemp_value}")
            if self.max_camtemp[0] == "N/A" or camtemp_value > self.max_camtemp[0]:
                self.max_camtemp = (camtemp_value, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                self.max_camtemp_label.config(text=f"Max Camtemp: {self.max_camtemp[0]} at {self.max_camtemp[1]}")
        if snstemp_value != "N/A":
            self.snstemp_label.config(text=f"Current Snstemp: {snstemp_value}")
            if self.max_snstemp[0] == "N/A" or snstemp_value > self.max_snstemp[0]:
                self.max_snstemp = (snstemp_value, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                self.max_snstemp_label.config(text=f"Max Snstemp: {self.max_snstemp[0]} at {self.max_snstemp[1]}")
        self.last_packet_label.config(text=f"Last Packet Read: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.packet_count_label.config(text=f"Packets Read: {total_packet_count}")
        
        # Check for threshold and show alert if necessary
        self.check_threshold(camtemp_value, snstemp_value)

    def check_threshold(self, camtemp_value, snstemp_value):
        try:
            camtemp_threshold = int(self.camtemp_threshold_entry.get())
            snstemp_threshold = int(self.snstemp_threshold_entry.get())
            
            if camtemp_value != "N/A" and camtemp_value > camtemp_threshold:
                threading.Thread(target=self.show_alert, args=("Camtemp Alert", f"Camtemp exceeded threshold: {camtemp_value}")).start()
            if snstemp_value != "N/A" and snstemp_value > snstemp_threshold:
                threading.Thread(target=self.show_alert, args=("Snstemp Alert", f"Snstemp exceeded threshold: {snstemp_value}")).start()
        except ValueError:
            print("Invalid threshold value")

    def show_alert(self, title, message):
        send_desktop_notification(title, message)

    def update_countdown(self):
        if self.monitoring:
            self.countdown -= 1
            if self.countdown <= 0:
                self.countdown = 10
            self.countdown_label.config(text=f"Next update in: {self.countdown}s")
            self.update_id = self.root.after(1000, self.update_countdown)

    def save_log(self, camtemp_value, snstemp_value, packet_count):
        log_file_path = self.get_log_file_path()
        with open(log_file_path, 'a') as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{camtemp_value},{snstemp_value},{packet_count}\n")

    def quit(self):
        if self.monitoring:
            self.root.after_cancel(self.update_id)
        self.root.destroy()

def main():
    try:
        root = tk.Tk()
        app = TemperatureMonitorApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Error initializing GUI: {e}")

if __name__ == "__main__":
    main()