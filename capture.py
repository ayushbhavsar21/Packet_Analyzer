from scapy.all import sniff
import threading

class PacketSniffer:
    def __init__(self, interface, callback):
        self.interface = interface
        self.callback = callback
        self.thread = None
        self.running = False

    def _sniff(self):
        sniff(iface=self.interface, prn=self.callback, stop_filter=lambda x: not self.running)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sniff, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
