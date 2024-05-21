import tkinter as tk
import threading
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import *
import queue


class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        # Menu bar setup
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        # File menu setup
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Exit", command=self.on_close)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        # Toolbar setup
        self.toolbar_frame = ttk.Frame(self.root)
        self.toolbar_frame.pack(side=tk.TOP, fill=tk.X)
        self.toolbar_label = ttk.Label(self.toolbar_frame, text="Sniffing Controls:")
        self.toolbar_label.pack(side=tk.LEFT, padx=5, pady=5)
        # Sniffing control buttons
        self.start_button = ttk.Button(self.toolbar_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.add_tooltip(self.start_button, "Start capturing packets")
        self.stop_button = ttk.Button(self.toolbar_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.add_tooltip(self.stop_button, "Stop capturing packets")
        # Packet display area
        self.packet_display_frame = ttk.Frame(self.root)
        self.packet_display_frame.pack(fill=tk.BOTH, expand=True)
        self.packet_info_label = ttk.Label(self.packet_display_frame, text="Packet Information:")
        self.packet_info_label.pack(pady=(10, 5))
        self.packet_display = scrolledtext.ScrolledText(self.packet_display_frame, wrap=tk.WORD, width=100, height=20)
        self.packet_display.pack(fill=tk.BOTH, expand=True)
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        # Internal state initialization
        self.packet_count = 0
        self.sniffing_thread = None
        self.stop_sniffing_flag = threading.Event()
        self.packet_queue = queue.Queue()
        self.detected_threats = []  # Correctly initialized here

        # Initialize detectors
        self.ddos_detector = DDoSDetector()
        self.malware_detector = MalwareDetector(["malware_signature1", "malware_signature2"])
        self.dns_detector = DNSDetector(["suspicious_domain1.com", "suspicious_domain2.net"])
        self.anomaly_detector = AnomalyDetector()
        self.payload_analyzer = PayloadAnalyzer(["malware_signature1", "malware_signature2"])
        
    def start_sniffing(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_count = 0
        self.packet_display.delete("1.0", tk.END)
        self.stop_sniffing_flag.clear()
        self.sniffing_thread = threading.Thread(target=self.sniff_packets)
        self.sniffing_thread.start()
        self.root.after(100, self.update_display)  # Start updating the display asynchronously

    def stop_sniffing(self):
        self.stop_sniffing_flag.set()
        self.generate_report()  # Generate the report when sniffing stops
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)

    def sniff_packets(self):
        sniff(prn=self.inspect_packet, stop_filter=lambda _: self.stop_sniffing_flag.is_set(), filter="tcp or udp")

    def inspect_packet(self, packet):
        if self.stop_sniffing_flag.is_set():
            return
        self.packet_count += 1
        packet_info = self.parse_packet(packet)
        self.process_packet(packet_info)

    def parse_packet(self, packet):
        src_ip, dst_ip, protocol_name, src_port, dst_port, packet_size = "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", 0

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_name = packet[IP].proto

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

        return src_ip, dst_ip, protocol_name, src_port, dst_port, len(packet), packet.payload

    def process_packet(self, packet_info):
        src_ip, dst_ip, protocol_name, src_port, dst_port, packet_size, packet_payload = packet_info

        suspicious = False
        threat_types = []

        if self.ddos_detector.detect(packet_info):
            suspicious = True
            threat_types.append(self.ddos_detector.threat_type)

        if self.malware_detector.detect(packet_payload):
            suspicious = True
            threat_types.append(self.malware_detector.threat_type)

        if self.dns_detector.detect(packet_info):
            suspicious = True
            threat_types.append(self.dns_detector.threat_type)

        if self.anomaly_detector.detect(packet_info):
            suspicious = True
            threat_types.append(self.anomaly_detector.threat_type)

        if self.payload_analyzer.detect(packet_info):
            suspicious = True
            threat_types.append(self.payload_analyzer.threat_type)

        if suspicious:
            threat_detail = (src_ip, dst_ip, protocol_name, src_port, dst_port, packet_size, packet_payload, threat_types)
            self.detected_threats.append(threat_detail)


        packet_display_text = f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol_name}, Source Port: {src_port}, Destination Port: {dst_port}, Size: {packet_size}\n"
        packet_display_text += f"Payload: {packet_payload}\n"
        packet_display_text += f"Suspicious: {'Yes' if suspicious else 'No'}, Threat Types: {', '.join(threat_types) if threat_types else 'None'}\n"
        packet_display_text += "--------------------------------------------------------\n"
        self.packet_queue.put(packet_display_text)

    def display_packet(self, packet_info, suspicious, threat_types):
        src_ip, dst_ip, protocol_name, src_port, dst_port, packet_size, packet_payload = packet_info

        packet_display_text = f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol_name}, Source Port: {src_port}, Destination Port: {dst_port}, Size: {packet_size}\n"
        packet_display_text += f"Payload: {packet_payload}\n"
        packet_display_text += f"Suspicious: {'Yes' if suspicious else 'No'}, Threat Types: {', '.join(threat_types) if threat_types else 'None'}\n"
        packet_display_text += "--------------------------------------------------------\n"

        self.packet_queue.put(packet_display_text)  # Put the text into the queue

    def update_display(self):
        while True:
            try:
                packet_display_text = self.packet_queue.get_nowait()  # Get the text from the queue
                self.packet_display.insert(tk.END, packet_display_text)  # Update the display
                self.packet_display.see(tk.END)  # Auto scroll to the end
            except queue.Empty:
                break

        self.root.after(100, self.update_display)  # Schedule the next update

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.stop_sniffing_flag.set()
            if self.sniffing_thread and self.sniffing_thread.is_alive():
                self.sniffing_thread.join()
            self.root.destroy()

    def add_tooltip(self, widget, text):
        def enter(event):
            self.tooltip = tk.Toplevel(self.root)
            self.tooltip.overrideredirect(True)
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 20
            self.tooltip.geometry(f"+{x}+{y}")
            ttk.Label(self.tooltip, text=text, padding=(5, 3), background="#ffffe0", relief="solid").pack()

        def leave(event):
            self.tooltip.destroy()

        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)


    def generate_report(self):
        if not self.detected_threats:
            messagebox.showinfo("Report Generated", "No threats detected.")
            return
    
        report_filename = "threats_report.txt"
        with open(report_filename, "w") as report_file:
            # Write a header for the report
            report_file.write("Threat Report\n")
            report_file.write("Generated at: {}\n\n".format(time.ctime()))
            report_file.write("Summary of detected threats:\n")
            report_file.write("---------------------------------\n")
    
            for threat in self.detected_threats:
                src_ip, dst_ip, protocol, src_port, dst_port, size, _payload, threat_types = threat
                # Format the threat details for readability
                report_entry = (
                    f"Source IP: {src_ip}\n"
                    f"Destination IP: {dst_ip}\n"
                    f"Protocol: {protocol}\n"
                    f"Source Port: {src_port}\n"
                    f"Destination Port: {dst_port}\n"
                    f"Packet Size: {size} bytes\n"
                    f"Threat Types: {', '.join(threat_types) if threat_types else 'None'}\n"
                    "---------------------------------\n"
                )
                report_file.write(report_entry)
    
        messagebox.showinfo("Report Generated", f"Threat report generated: {report_filename}")


class DDoSDetector:
    def __init__(self, ddos_threshold=100, packet_rate_threshold=1000, time_window=60):
        self.ddos_threshold = ddos_threshold
        self.packet_rate_threshold = packet_rate_threshold
        self.time_window = time_window
        self.packet_count = 0
        self.packet_timestamps = []

    def detect(self, packet_info):
        self.packet_count += 1
        self.packet_timestamps.append(time.time())
        if self.packet_count >= self.ddos_threshold:
            if self.is_sudden_spike():
                return True
        return False

    def is_sudden_spike(self):
        if len(self.packet_timestamps) < 2:
            return False
        
        current_time = time.time()
        time_diff = current_time - self.packet_timestamps[0]
        
        if time_diff <= self.time_window:
            packet_rate = len(self.packet_timestamps) / time_diff
            if packet_rate > self.packet_rate_threshold:
                return True
        
        return False
    
class MalwareDetector:
    def __init__(self, malware_signatures):
        self.malware_signatures = malware_signatures

    def detect(self, packet_payload):
        for signature in self.malware_signatures:
            if signature in packet_payload:
                return True
        return False

    @property
    def threat_type(self):
        return "Malware Payload"


class DNSDetector:
    def __init__(self, suspicious_domains):
        self.suspicious_domains = suspicious_domains

    def detect(self, packet):
        if DNS in packet and hasattr(packet[DNS], 'qd') and hasattr(packet[DNS].qd, 'qname'):
            query = packet[DNS].qd.qname.decode().lower()  # Extract the DNS query and convert it to lowercase
            for domain in self.suspicious_domains:
                if domain in query:
                    return True
        return False

    @property
    def threat_type(self):
        return "Suspicious DNS Query"


class AnomalyDetector:
    def __init__(self, payload_threshold=1000):
        self.payload_threshold = payload_threshold

    def detect(self, packet_data):
        packet_size = int(packet_data[5])
        if packet_size > self.payload_threshold:
            return True
        return False

    @property
    def threat_type(self):
        return "Large Payload"


class PayloadAnalyzer:
    def __init__(self, malware_signatures=None):
        self.malware_signatures = malware_signatures or []

    def detect(self, packet_payload):
        if isinstance(packet_payload, bytes):
            packet_payload = packet_payload.decode()  # Convert bytes to string
        elif not isinstance(packet_payload, str):
            packet_payload = str(packet_payload)  # Convert non-string objects to string
        for signature in self.malware_signatures:
            if re.search(re.escape(signature), packet_payload, re.IGNORECASE):  # Escape special characters in the signature
                return True
        return False


def main():
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
