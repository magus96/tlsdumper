import ssl
import os
import json
import re
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import pyshark
from threading import Thread
from dataclasses import dataclass, asdict
from typing import Dict, List, Any
from datetime import datetime

CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"

@dataclass
class EthernetLayer:
    destination: str
    source: str
    type: str
    lg_bit: str
    ig_bit: str

@dataclass
class IPLayer:
    version: str
    header_length: str
    dscp: str
    ecn: str
    total_length: str
    identification: str
    flags: str
    fragment_offset: str
    ttl: str
    protocol: str
    header_checksum: str
    source_address: str
    destination_address: str

@dataclass
class TCPLayer:
    source_port: str
    destination_port: str
    stream_index: str
    tcp_segment_len: str
    sequence_number: str
    acknowledgment_number: str
    header_length: str
    flags: str
    window: str
    checksum: str
    urgent_pointer: str
    options: str

@dataclass
class TLSLayer:
    content_type: str
    version: str
    length: str
    handshake_type: str
    handshake_length: str
    client_version: str
    random: str
    session_id: str
    cipher_suites: List[str]
    compression_methods: List[str]
    extensions: Dict[str, Any]
    ja3_fullstring: str
    ja3_hash: str

class PacketParser:
    def __init__(self, raw_data: str):
        self.raw_data = raw_data
        self.clean_data = self._remove_ansi_codes(raw_data)
        
    def _remove_ansi_codes(self, text: str) -> str:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def _extract_field_value(self, pattern: str, text: str) -> str:
        try:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            return match.group(1).strip() if match else ""
        except Exception as e:
            print(f"⚠️  Regex error for pattern '{pattern}': {str(e)}")
            return ""
    
    def _extract_all_matches(self, pattern: str, text: str) -> List[str]:
        try:
            return re.findall(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        except Exception as e:
            print(f"⚠️  Regex error for pattern '{pattern}': {str(e)}")
            return []
    
    def parse_ethernet_layer(self) -> EthernetLayer:
        return EthernetLayer(
            destination=self._extract_field_value(r"Destination:\s*([^\n]+)", self.clean_data),
            source=self._extract_field_value(r"Source:\s*([^\n]+)", self.clean_data),
            type=self._extract_field_value(r"Type:\s*([^\n]+)", self.clean_data),
            lg_bit=self._extract_field_value(r"LG bit:\s*([^\n]+)", self.clean_data),
            ig_bit=self._extract_field_value(r"IG bit:\s*([^\n]+)", self.clean_data)
        )
    
    def parse_ip_layer(self) -> IPLayer:
        try:
            return IPLayer(
                version=self._extract_field_value(r"Version:\s*(\d+)", self.clean_data),
                header_length=self._extract_field_value(r"Header Length:\s*([^\n]+)", self.clean_data),
                dscp=self._extract_field_value(r"DSCP:\s*([^,\n\)]+)", self.clean_data),
                ecn=self._extract_field_value(r"ECN:\s*([^\)\n]+)", self.clean_data),
                total_length=self._extract_field_value(r"Total Length:\s*(\d+)", self.clean_data),
                identification=self._extract_field_value(r"Identification:\s*([^\n]+)", self.clean_data),
                flags=self._extract_field_value(r"Flags:\s*([^\n]+)", self.clean_data),
                fragment_offset=self._extract_field_value(r"Fragment Offset:\s*(\d+)", self.clean_data),
                ttl=self._extract_field_value(r"Time to Live:\s*(\d+)", self.clean_data),
                protocol=self._extract_field_value(r"Protocol:\s*([^\n]+)", self.clean_data),
                header_checksum=self._extract_field_value(r"Header Checksum:\s*([^\n\[]+)", self.clean_data),
                source_address=self._extract_field_value(r"Source Address:\s*([^\n]+)", self.clean_data),
                destination_address=self._extract_field_value(r"Destination Address:\s*([^\n]+)", self.clean_data)
            )
        except Exception as e:
            print(f"⚠️  Error parsing IP layer: {str(e)}")
            return IPLayer("", "", "", "", "", "", "", "", "", "", "", "", "")
    
    def parse_tcp_layer(self) -> TCPLayer:
        return TCPLayer(
            source_port=self._extract_field_value(r"Source Port:\s*([^\n]+)", self.clean_data),
            destination_port=self._extract_field_value(r"Destination Port:\s*([^\n]+)", self.clean_data),
            stream_index=self._extract_field_value(r"Stream index:\s*([^\n]+)", self.clean_data),
            tcp_segment_len=self._extract_field_value(r"TCP Segment Len:\s*([^\n]+)", self.clean_data),
            sequence_number=self._extract_field_value(r"Sequence Number:\s*([^\n]+)", self.clean_data),
            acknowledgment_number=self._extract_field_value(r"Acknowledgment Number:\s*([^\n]+)", self.clean_data),
            header_length=self._extract_field_value(r"Header Length:\s*([^\n]+)", self.clean_data),
            flags=self._extract_field_value(r"TCP Flags:\s*([^\n]+)", self.clean_data),
            window=self._extract_field_value(r"Window:\s*([^\n]+)", self.clean_data),
            checksum=self._extract_field_value(r"Checksum:\s*([^\n]+)", self.clean_data),
            urgent_pointer=self._extract_field_value(r"Urgent Pointer:\s*([^\n]+)", self.clean_data),
            options=self._extract_field_value(r"Options:\s*([^\n]+)", self.clean_data)
        )
    
    def parse_tls_extensions(self) -> Dict[str, Any]:
        extensions = {}
        
        # Server Name
        server_name = self._extract_field_value(r"Server Name:\s*([^\n]+)", self.clean_data)
        if server_name:
            extensions['server_name'] = server_name
        
        # Supported Groups
        supported_groups = self._extract_all_matches(r"Supported Group:\s*([^\n]+)", self.clean_data)
        if supported_groups:
            extensions['supported_groups'] = supported_groups
        
        # Signature Algorithms
        signature_algorithms = self._extract_all_matches(r"Signature Algorithm:\s*([^\n]+)", self.clean_data)
        if signature_algorithms:
            extensions['signature_algorithms'] = signature_algorithms
        
        # ALPN Protocols
        alpn_protocols = self._extract_all_matches(r"ALPN Next Protocol:\s*([^\n]+)", self.clean_data)
        if alpn_protocols:
            extensions['alpn_protocols'] = alpn_protocols
        
        # Supported Versions
        supported_versions = self._extract_all_matches(r"Supported Version:\s*([^\n]+)", self.clean_data)
        if supported_versions:
            extensions['supported_versions'] = supported_versions
        
        return extensions
    
    def parse_tls_layer(self) -> TLSLayer:
        try:
            # Extract cipher suites - be more flexible with the pattern
            cipher_suites = self._extract_all_matches(r"Cipher Suite:\s*([^\n]+)", self.clean_data)
            
            # Extract compression methods
            compression_methods = self._extract_all_matches(r"Compression Method:\s*([^\n]+)", self.clean_data)
            
            # More robust version extraction for TLS
            tls_version = self._extract_field_value(r"Version:\s*(TLS[^\n\(]+)", self.clean_data)
            if not tls_version:
                tls_version = self._extract_field_value(r"TLS.*?(\d\.\d)", self.clean_data)
            
            return TLSLayer(
                content_type=self._extract_field_value(r"Content Type:\s*([^\n]+)", self.clean_data),
                version=tls_version,
                length=self._extract_field_value(r"Length:\s*(\d+)", self.clean_data),
                handshake_type=self._extract_field_value(r"Handshake Type:\s*([^\n]+)", self.clean_data),
                handshake_length=self._extract_field_value(r"(?:Handshake Protocol:.*?)?Length:\s*(\d+)", self.clean_data),
                client_version=self._extract_field_value(r"Version:\s*TLS\s*([^\n\(]+)", self.clean_data),
                random=self._extract_field_value(r"Random:\s*([a-fA-F0-9]+)", self.clean_data),
                session_id=self._extract_field_value(r"Session ID:\s*([a-fA-F0-9]+)", self.clean_data),
                cipher_suites=cipher_suites,
                compression_methods=compression_methods,
                extensions=self.parse_tls_extensions(),
                ja3_fullstring=self._extract_field_value(r"JA3 Fullstring:\s*([^\n]+)", self.clean_data),
                ja3_hash=self._extract_field_value(r"JA3:\s*([a-fA-F0-9]+)", self.clean_data)
            )
        except Exception as e:
            print(f"⚠️  Error parsing TLS layer: {str(e)}")
            return TLSLayer("", "", "", "", "", "", "", "", [], [], {}, "", "")
    
    def parse_packet_info(self) -> Dict[str, Any]:
        return {
            'packet_length': self._extract_field_value(r"Packet \(Length: (\d+)\)", self.clean_data),
            'timestamp_info': {
                'time_since_first_frame': self._extract_field_value(r"Time since first frame in this TCP stream:\s*([^\n]+)", self.clean_data),
                'time_since_previous_frame': self._extract_field_value(r"Time since previous frame in this TCP stream:\s*([^\n]+)", self.clean_data),
                'irtt': self._extract_field_value(r"iRTT:\s*([^\n]+)", self.clean_data)
            },
            'tcp_analysis': {
                'bytes_in_flight': self._extract_field_value(r"Bytes in flight:\s*([^\n]+)", self.clean_data),
                'bytes_sent_since_psh': self._extract_field_value(r"Bytes sent since last PSH flag:\s*([^\n]+)", self.clean_data),
                'conversation_completeness': self._extract_field_value(r"Conversation completeness:\s*([^\n]+)", self.clean_data)
            }
        }
    
    def extract_all_info(self) -> Dict[str, Any]:
        packet_info = {}
        
        try:
            packet_info['packet_info'] = self.parse_packet_info()
        except Exception as e:
            print(f"⚠️  Error parsing packet info: {str(e)}")
            packet_info['packet_info'] = {}
        
        try:
            packet_info['ethernet_layer'] = asdict(self.parse_ethernet_layer())
        except Exception as e:
            print(f"⚠️  Error parsing ethernet layer: {str(e)}")
            packet_info['ethernet_layer'] = {}
        
        try:
            packet_info['ip_layer'] = asdict(self.parse_ip_layer())
        except Exception as e:
            print(f"⚠️  Error parsing IP layer: {str(e)}")
            packet_info['ip_layer'] = {}
        
        try:
            packet_info['tcp_layer'] = asdict(self.parse_tcp_layer())
        except Exception as e:
            print(f"⚠️  Error parsing TCP layer: {str(e)}")
            packet_info['tcp_layer'] = {}
        
        try:
            packet_info['tls_layer'] = asdict(self.parse_tls_layer())
        except Exception as e:
            print(f"⚠️  Error parsing TLS layer: {str(e)}")
            packet_info['tls_layer'] = {}
        
        return packet_info

class TLSCaptureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        version = query.get("version", ["unknown"])[0]
        
        if version == "unknown":
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing version parameter\n")
            return
        
        browser = version.split("_")[0]
        version_number = version.split("_")[1] if "_" in version else "unknown"
        
        print(f"[+] Got request from {self.client_address[0]} with version={version}")
        
        # Spawn capture thread
        capture_thread = Thread(
            target=capture_tls_handshake,
            args=(browser, version_number),
            daemon=True
        )
        capture_thread.start()
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Capture started\n")

def save_packet_data(raw_data: str, browser: str, version: str) -> None:
    try:
        # Parse the packet data
        print(f"[*] Parsing TLS handshake data for {browser} {version}...")
        parser = PacketParser(raw_data)
        extracted_info = parser.extract_all_info()
        
        # Add metadata
        extracted_info['metadata'] = {
            'captured_at': datetime.now().isoformat(),
            'browser': browser,
            'version': version,
            'parser_version': '1.0'
        }
        
        # Create directory structure
        save_dir = f"handshakes/{browser}/{version}"
        os.makedirs(save_dir, exist_ok=True)
        
        # Save raw data (original format)
        raw_data_dict = {"raw": raw_data}
        raw_path = f"{save_dir}/{version}.json"
        with open(raw_path, "w") as f:
            json.dump(raw_data_dict, f, indent=2)
        print(f"[+] Raw TLS handshake saved to {raw_path}")
        
        # Save detailed analysis
        detailed_path = f"{save_dir}/{version}_detailedanalysis.json"
        with open(detailed_path, "w") as f:
            json.dump(extracted_info, f, indent=2, ensure_ascii=False)
        print(f"[+] Detailed analysis saved to {detailed_path}")
                
        
    except Exception as e:
        print(f"[!] Error parsing packet data: {e}")
        # Still save raw data even if parsing fails
        save_dir = f"handshakes/{browser}/{version}"
        os.makedirs(save_dir, exist_ok=True)
        raw_path = f"{save_dir}/{version}.json"
        with open(raw_path, "w") as f:
            json.dump({"raw": raw_data, "error": str(e)}, f, indent=2)
        print(f"[+] Raw data saved to {raw_path} (with error info)")

def capture_tls_handshake(browser, version):
    print(f"[*] Starting TLS capture for {browser} {version}...")
    
    capture = pyshark.LiveCapture(
        interface='lo',
        display_filter='tls.handshake.type == 1',  # Client Hello
    )
    
    try:
        print("[*] Waiting for TLS Client Hello packets...")
        capture.sniff(timeout=10)
        
        for packet in capture:
            if "tls" in packet:
                print(f"[+] Captured TLS Client Hello from {browser} {version}")
                
                # Get raw packet data
                raw_packet_data = str(packet)
                
                # Parse and save the data
                save_packet_data(raw_packet_data, browser, version)
                break
        else:
            print("[-] No TLS Client Hello packets found within timeout period")
            
    except Exception as e:
        print(f"[!] Error during capture: {e}")
    finally:
        capture.close()

def run_server():
    server_address = ('localhost', 8443)
    httpd = HTTPServer(server_address, TLSCaptureHandler)
    
    # Use SSLContext instead of deprecated ssl.wrap_socket
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print("[*] HTTPS server running at https://localhost:8443")
    print("[*] Send requests with ?version=browser_version (e.g., ?version=chrome_120)")
    print("[*] Files will be saved as:")
    print("    - handshakes/{browser}/{version}/{version}.json (raw data)")
    print("    - handshakes/{browser}/{version}/{version}_detailedanalysis.json (parsed data)")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server shutdown requested")
        httpd.shutdown()

if __name__ == "__main__":
    run_server()