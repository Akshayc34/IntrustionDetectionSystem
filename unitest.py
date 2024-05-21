#unitest.py
import unittest
from scapy.all import IP, UDP, DNS, DNSQR
from test import DDoSDetector, DNSDetector, AnomalyDetector, PayloadAnalyzer
import time
import logging

class TestDDoSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DDoSDetector()

    def test_detect_with_spike(self):
        # Simulate a sudden spike in packet rate
        self.detector.packet_timestamps.extend([time.time() - i for i in range(10)])  # Add some timestamps
        
        # Log packet timestamps before calling is_sudden_spike method
        logging.debug("Before calling is_sudden_spike method:")
        logging.debug("Packet timestamps: %s", self.detector.packet_timestamps)
        
        # Call is_sudden_spike method
        detection_result = self.detector.is_sudden_spike()
        
        # Log detection result
        logging.debug("After calling is_sudden_spike method:")
        logging.debug("Detection result: %s", detection_result)
        
        # Assert the detection result
        self.assertTrue(detection_result)
        

class TestDNSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DNSDetector(["suspicious_domain1.com", "suspicious_domain2.net"])

    def test_detect_with_match(self):
        packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="suspicious_domain1.com"))
        self.assertTrue(self.detector.detect(packet))

    def test_detect_no_match(self):
        packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com"))
        self.assertFalse(self.detector.detect(packet))


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector()

    def test_detect_large_payload(self):
        packet_data = ("src_ip", "dst_ip", "protocol_name", "src_port", "dst_port", 1500, "payload")
        self.assertTrue(self.detector.detect(packet_data))

    def test_detect_small_payload(self):
        packet_data = ("src_ip", "dst_ip", "protocol_name", "src_port", "dst_port", 500, "payload")
        self.assertFalse(self.detector.detect(packet_data))


class TestPayloadAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PayloadAnalyzer(["malware_signature1", "malware_signature2"])

    def test_detect_malware_with_match(self):
        packet_payload = "This is a malicious packet with malware_signature1"
        self.assertTrue(self.analyzer.detect(packet_payload))

    def test_detect_malware_no_match(self):
        packet_payload = "This is a normal packet without any malware signature"
        self.assertFalse(self.analyzer.detect(packet_payload))


if __name__ == "__main__":
    unittest.main()
