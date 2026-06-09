import sys
import time
import socket
import threading
import logging
from typing import Dict, Any, Optional, Callable
import psutil
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR

import config

logger = logging.getLogger(__name__)

class DNSSniffer:
    def __init__(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Initializes the DNS sniffer.
        :param callback: Function to call with enriched raw event dictionaries
        """
        self.callback = callback
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.port_pid_map: Dict[int, int] = {}
        self.last_map_update = 0.0
        self.map_lock = threading.Lock()
        
        # Track simulated traffic index
        self.simulation_index = 0

    def start(self):
        """Starts sniffing DNS events (either real or simulated)."""
        self.running = True
        if config.SIMULATION_MODE:
            logger.info("Starting DNS Sniffer in SIMULATION MODE...")
            self.sniffer_thread = threading.Thread(target=self._run_simulation, daemon=True)
        else:
            logger.info(f"Starting DNS Sniffer on interface {config.SNIFFER_INTERFACE or 'ALL'}...")
            self.sniffer_thread = threading.Thread(target=self._run_sniffing, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Stops the sniffer thread."""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2.0)
            logger.info("DNS Sniffer stopped.")

    def _update_port_pid_map(self):
        """
        Queries system network connections to map UDP ports to PIDs.
        Rate limited to protect system performance.
        """
        now = time.time()
        # Update connection map at most once every 1.0 seconds
        if now - self.last_map_update < 1.0:
            return
            
        with self.map_lock:
            try:
                new_map = {}
                for conn in psutil.net_connections(kind='udp'):
                    if conn.laddr and conn.pid:
                        new_map[conn.laddr.port] = conn.pid
                self.port_pid_map = new_map
                self.last_map_update = now
            except Exception as e:
                logger.debug(f"Failed to update port-to-PID map: {e}")

    def _get_pid_by_sport(self, sport: int) -> int:
        """Looks up the local PID responsible for a local UDP source port."""
        self._update_port_pid_map()
        with self.map_lock:
            return self.port_pid_map.get(sport, 0)

    def _packet_callback(self, packet):
        """Callback executed by Scapy for every sniffed packet."""
        try:
            if not packet.haslayer(DNS):
                return

            dns_layer = packet[DNS]
            
            # We process both requests and responses
            # Determine if this is a query (qr=0) or response (qr=1)
            is_response = dns_layer.qr == 1
            
            # Get transport layer details
            src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "0.0.0.0"
            sport = packet[UDP].sport if packet.haslayer(UDP) else 0
            dport = packet[UDP].dport if packet.haslayer(UDP) else 0

            # Determine PID. If outgoing query, sport is the source process port.
            # If incoming response, dport is the local process port.
            local_port = sport if not is_response else dport
            pid = self._get_pid_by_sport(local_port)

            # Core DNS parameters
            query_name = ""
            query_type = "A"
            
            if dns_layer.qd:
                # Scapy decodes queries into bytes, decode it to string
                qname = dns_layer.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="ignore")
                query_name = qname.rstrip(".")
                
                # Query Type (A, AAAA, TXT, MX, NS, CNAME)
                query_type_id = dns_layer.qd.qtype
                # Map standard integers to human readable names
                query_type_map = {
                    1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 2: "NS", 5: "CNAME", 12: "PTR", 255: "ANY"
                }
                query_type = query_type_map.get(query_type_id, f"TYPE-{query_type_id}")

            # Parse response answers if available
            response_code = "NOERROR"
            response_ips = []
            response_cnames = []
            ttl = 0

            if is_response:
                # Map RCODE to string representation
                rcode_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
                response_code = rcode_map.get(dns_layer.rcode, f"RCODE-{dns_layer.rcode}")
                
                # Extract records
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    if answer.type == 1:  # A Record
                        response_ips.append(answer.rdata)
                        ttl = answer.ttl
                    elif answer.type == 28:  # AAAA
                        response_ips.append(answer.rdata)
                        ttl = answer.ttl
                    elif answer.type == 5:  # CNAME
                        cname = answer.rdata
                        if isinstance(cname, bytes):
                            cname = cname.decode("utf-8", errors="ignore")
                        response_cnames.append(cname.rstrip("."))
                        ttl = answer.ttl

            # Build Raw Event
            raw_event = {
                "event_id": "",  # To be filled by correlation engine
                "timestamp": "",  # To be filled by correlation engine
                "client_ip": src_ip if not is_response else dst_ip,
                "query": query_name,
                "query_type": query_type,
                "response_code": response_code,
                "response_ip": response_ips,
                "response_cname": response_cnames,
                "ttl": ttl,
                "recursive": True if dns_layer.rd == 1 else False,
                "authoritative": True if dns_layer.aa == 1 else False,
                "pid": pid,
                "network_details": {
                    "source_port": sport,
                    "destination_port": dport,
                    "transport": "UDP"
                }
            }
            
            # Send raw event to main correlation engine
            self.callback(raw_event)

        except Exception as e:
            logger.error(f"Error parsing sniffed packet: {e}", exc_info=True)

    def _run_native_windows_sniffing(self):
        """
        Fallback sniffer using native Windows raw sockets.
        Requires Admin privileges, but does NOT require Npcap/WinPcap.
        """
        logger.info("Attempting native Windows raw socket sniffing...")
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Create raw IP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            logger.info(f"Native Windows sniffer successfully bound to {local_ip}")
            
            while self.running:
                try:
                    # Receive raw packet bytes
                    packet_bytes, _ = s.recvfrom(65535)
                    
                    # Parse using Scapy's parser (which still works for decoding raw bytes)
                    packet = IP(packet_bytes)
                    
                    # Filter for UDP port 53 (DNS)
                    if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
                        self._packet_callback(packet)
                except Exception as pe:
                    # Occasional parse/receive errors can happen on raw interfaces, log but continue
                    logger.debug(f"Error reading/parsing raw packet: {pe}")
                    
        except Exception as e:
            logger.error(f"Native Windows sniffing failed: {e}. Falling back to simulation mode.")
            config.SIMULATION_MODE = True
            self._run_simulation()

    def _run_sniffing(self):
        """Scapy sniffing loop."""
        try:
            # Filter for UDP traffic on Port 53 (DNS)
            sniff(
                filter="udp port 53",
                prn=self._packet_callback,
                iface=config.SNIFFER_INTERFACE,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.warning(f"Scapy sniffing failed: {e}. Trying native Windows raw socket...")
            if sys.platform == "win32":
                self._run_native_windows_sniffing()
            else:
                logger.error("Not on Windows, falling back to simulation mode.")
                config.SIMULATION_MODE = True
                self._run_simulation()

    def _run_simulation(self):
        """Simulates periodic DNS packets for testing without administrative sniffing rights."""
        # Find a few real local PIDs to inject into simulation to make the lineage real!
        real_pids = []
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if p.info['name'].lower() in ['chrome.exe', 'powershell.exe', 'cmd.exe', 'explorer.exe', 'svchost.exe', 'python.exe']:
                    real_pids.append((p.info['pid'], p.info['name']))
            except Exception:
                continue
        if not real_pids:
            real_pids = [(1024, "chrome.exe"), (4096, "powershell.exe"), (2132, "cmd.exe"), (922, "svchost.exe")]

        # Define simulated events
        simulated_scenarios = [
            # Scenario 1: Normal web browsing (Clean)
            {
                "client_ip": "192.168.1.52",
                "query": "github.com",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["140.82.121.4"],
                "response_cname": [],
                "ttl": 3600,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "chrome.exe",
                "simulated_pid_override": None
            },
            # Scenario 2: Typosquatting domain requested by PowerShell (Highly suspicious)
            {
                "client_ip": "192.168.1.52",
                "query": "micros0ft-login.xyz",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["185.220.101.5"],  # Tor Exit Node
                "response_cname": ["malicious-redirector.ru"],
                "ttl": 60,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "powershell.exe",
                "simulated_pid_override": None
            },
            # Scenario 3: DGA malware beaconing (Suspicious SLD structure)
            {
                "client_ip": "192.168.1.52",
                "query": "qwe921x.biz",
                "query_type": "A",
                "response_code": "NXDOMAIN",
                "response_ip": [],
                "response_cname": [],
                "ttl": 0,
                "recursive": True,
                "authoritative": True,
                "pid_name_fallback": "svchost.exe",
                "simulated_pid_override": None
            },
            # Scenario 4: DNS Tunneling - Exfiltration of Base64 credentials
            {
                "client_ip": "192.168.1.52",
                "query": "aGVsbG8td29ybGQ.attacker-c2.ru",
                "query_type": "TXT",
                "response_code": "NOERROR",
                "response_ip": [],
                "response_cname": [],
                "ttl": 30,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "cmd.exe",
                "simulated_pid_override": None
            },
            # Scenario 5: DNS Tunneling - Heavy traffic chunk 2
            {
                "client_ip": "192.168.1.52",
                "query": "dGhpcyBpcyBhIHRlc3Q.attacker-c2.ru",
                "query_type": "TXT",
                "response_code": "NOERROR",
                "response_ip": [],
                "response_cname": [],
                "ttl": 30,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "cmd.exe",
                "simulated_pid_override": None
            },
            # Scenario 6: Normal DNS MX lookup for mail delivery
            {
                "client_ip": "192.168.1.52",
                "query": "gmail.com",
                "query_type": "MX",
                "response_code": "NOERROR",
                "response_ip": ["142.250.183.14"],
                "response_cname": [],
                "ttl": 300,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "chrome.exe",
                "simulated_pid_override": None
            },
            # Scenario 7: Fast Flux Resolution (Low TTL, changing IPs)
            {
                "client_ip": "192.168.1.52",
                "query": "dynamic-dns-malware.ru",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["91.202.4.15", "203.91.48.2", "185.44.12.9"],
                "response_cname": [],
                "ttl": 10,  # Fast flux indicator
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "svchost.exe",
                "simulated_pid_override": None
            },
            # Scenario 8: Split-Brain DNS domain portal.company.com
            {
                "client_ip": "192.168.1.52",
                "query": "portal.company.com",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["10.0.0.15"],  # Returns internal network range
                "response_cname": [],
                "ttl": 3600,
                "recursive": True,
                "authoritative": True,
                "pid_name_fallback": "chrome.exe",
                "simulated_pid_override": None
            },
            # Scenario 9: iPhone user accessing fake WEEX cryptocurrency website (Coruna Exploit Kit)
            {
                "client_ip": "192.168.1.52",
                "query": "3v5w1km5gv.xyz",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["185.220.101.5"],
                "response_cname": [],
                "ttl": 60,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "chrome.exe",
                "simulated_pid_override": None
            },
            # Scenario 10: Watering hole targeting Ukrainian users (Coruna exploit kit hosting)
            {
                "client_ip": "192.168.1.52",
                "query": "cdn.uacounter.com",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["185.220.101.5"],
                "response_cname": [],
                "ttl": 60,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "chrome.exe",
                "simulated_pid_override": None
            },
            # Scenario 11: PLASMAGRID C2 DGA domain lookup
            {
                "client_ip": "192.168.1.52",
                "query": "ztvnhmhm4zj95w3.xyz",
                "query_type": "A",
                "response_code": "NOERROR",
                "response_ip": ["185.220.101.5"],
                "response_cname": [],
                "ttl": 60,
                "recursive": True,
                "authoritative": False,
                "pid_name_fallback": "chrome.exe",
                "simulated_pid_override": None
            }
        ]

        logger.info(f"Simulating {len(simulated_scenarios)} diverse security scenarios...")
        
        while self.running:
            try:
                # Cycle through scenarios
                scenario = simulated_scenarios[self.simulation_index % len(simulated_scenarios)]
                self.simulation_index += 1
                
                # Match pid name to a real running process on this machine to show real lineage!
                target_pid = 0
                for pid, name in real_pids:
                    if name.lower() == scenario["pid_name_fallback"].lower():
                        target_pid = pid
                        break
                
                if target_pid == 0 and real_pids:
                    # Default fallback
                    target_pid = real_pids[0][0]
                    
                # Create raw simulated event
                raw_event = {
                    "event_id": "",  # Filled by correlation engine
                    "timestamp": "",  # Filled by correlation engine
                    "client_ip": scenario["client_ip"],
                    "query": scenario["query"],
                    "query_type": scenario["query_type"],
                    "response_code": scenario["response_code"],
                    "response_ip": scenario["response_ip"],
                    "response_cname": scenario["response_cname"],
                    "ttl": scenario["ttl"],
                    "recursive": scenario["recursive"],
                    "authoritative": scenario["authoritative"],
                    "pid": target_pid,
                    "network_details": {
                        "source_port": 50123 + (self.simulation_index % 1000),
                        "destination_port": 53,
                        "transport": "UDP"
                    }
                }
                
                # Call callback
                self.callback(raw_event)
                
                # Wait before generating next event (e.g. every 4 seconds)
                time.sleep(4.0)
                
            except Exception as e:
                logger.error(f"Error in simulation loop: {e}", exc_info=True)
                time.sleep(5.0)
