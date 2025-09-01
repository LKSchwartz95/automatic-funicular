import subprocess
import json
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Generator
from datetime import datetime

from .event_model import Event
from .config import ConfigLoader
from .rules import http_rules, smtp_rules, pop3_imap_rules, ftp_rules, telnet_rules, tls_rules

logger = logging.getLogger(__name__)


class NetworkDetector:
    def __init__(self, config: ConfigLoader):
        self.config = config
        self.allowlist_networks = self._build_allowlist()
        self.credential_keys = set(config.get_credential_keys())
        self.max_body_size = config.get_max_body_size()
        
        # Build tshark command
        self.tshark_cmd = self._build_tshark_command()
        
        logger.info(f"Network detector initialized with interface: {config.get('detector.interface')}")
        logger.info(f"Tshark path: {config.get('detector.tshark_path')}")

    def _build_allowlist(self) -> List[ipaddress.IPv4Network]:
        """Build allowlist networks from configuration."""
        networks = []
        for cidr in self.config.get_allowlist_cidrs():
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                networks.append(network)
                logger.info(f"Added allowlist network: {cidr}")
            except ValueError as e:
                logger.warning(f"Invalid CIDR in allowlist: {cidr} - {e}")
        return networks

    def _build_tshark_command(self) -> List[str]:
        """Build tshark command with proper options."""
        detector_config = self.config.get_detector_config()
        
        # Base command
        cmd = [
            detector_config["tshark_path"],
            "-i", detector_config["interface"],
            "-l",  # line-buffered
            "-T", "json",
            "-n",  # disable name resolution for performance
            "-o", "tcp.desegment_tcp_streams:true",
            "-o", "http.desegment_body:true",
        ]

        # Display filter for all enabled TCP-based protocols
        display_filters = []
        if self.config.is_protocol_enabled("http"):
            display_filters.append("http")
        if self.config.is_protocol_enabled("smtp"):
            display_filters.append("smtp")
        if self.config.is_protocol_enabled("imap_pop3"):
            display_filters.append("pop or imap")
        if self.config.is_protocol_enabled("ftp"):
            display_filters.append("ftp")
        if self.config.is_protocol_enabled("telnet"):
            display_filters.append("telnet")
        if self.config.is_protocol_enabled("tls"):
            # This filter captures the TLS handshake (ClientHello is type 1)
            display_filters.append("tls.handshake.type == 1")

        if display_filters:
            cmd.extend(["-Y", " or ".join(display_filters)])

        # Add BPF filter if specified
        if detector_config.get("bpf"):
            cmd.extend(["-f", detector_config["bpf"]])
            
        return cmd

    def _is_allowlisted(self, ip: str) -> bool:
        """Check if IP is in allowlist."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.allowlist_networks)
        except ValueError:
            return False

    def _extract_packet_info(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract basic packet information from tshark output."""
        try:
            timestamp = datetime.fromtimestamp(float(packet["_source"]["layers"]["frame"]["frame.time_epoch"]))
            layers = packet.get("_source", {}).get("layers", {})
            if not isinstance(layers, dict):
                return None
                
            # Extract IP layer
            ip_layer = layers.get("ip") or layers.get("ipv6")
            if not ip_layer:
                return None
                
            # Extract TCP layer
            tcp_layer = layers.get("tcp")
            if not tcp_layer:
                return None
                
            src_ip = ip_layer.get("ip.src") or ip_layer.get("ipv6.src")
            dst_ip = ip_layer.get("ip.dst") or ip_layer.get("ipv6.dst")
            src_port = int(tcp_layer.get("tcp.srcport", 0))
            dst_port = int(tcp_layer.get("tcp.dstport", 0))
            
            if not all([src_ip, dst_ip, src_port, dst_port]):
                return None
                
            return {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "layers": layers
            }
            
        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Error extracting packet info: {e}")
            return None

    def start_capture(self) -> Generator[Event, None, None]:
        """Start packet capture and yield security events."""
        logger.info(f"Starting packet capture with command: {' '.join(self.tshark_cmd)}")
        
        try:
            process = subprocess.Popen(
                self.tshark_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            logger.info(f"Tshark process started with PID: {process.pid}")
            
            # Process output line by line
            for line in process.stdout:
                try:
                    # tshark can sometimes output multiple JSON objects on one line
                    for jsonObj in json.loads(f'[{line.strip().replace("}{", "},{")}]'):
                        event = self._process_packet(jsonObj)
                        if event:
                            yield event
                            
                except json.JSONDecodeError as e:
                    logger.debug(f"JSON decode error on line: {line.strip()} - {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            raise
        finally:
            if 'process' in locals() and process.poll() is None:
                process.terminate()
                logger.info("Tshark process terminated")

    def _process_packet(self, packet: Dict[str, Any]) -> Optional[Event]:
        """Process a single packet and return security event if found."""
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return None
            
        # Check if destination is allowlisted
        if self._is_allowlisted(packet_info["dst_ip"]):
            return None
            
        layers = packet_info["layers"]
        
        # Process protocols based on configuration
        event: Optional[Event] = None

        # HTTP
        if self.config.is_protocol_enabled("http") and "http" in layers:
            event = http_rules.process_http_packet(
                layers["http"], packet_info, self.credential_keys, self.max_body_size
            )
            if event: return event

        # SMTP
        if self.config.is_protocol_enabled("smtp") and "smtp" in layers:
            event = smtp_rules.process_smtp_packet(layers["smtp"], packet_info)
            if event: return event

        # POP3/IMAP
        if self.config.is_protocol_enabled("imap_pop3"):
            pop3_layer = layers.get("pop") or layers.get("pop3")
            imap_layer = layers.get("imap")
            if pop3_layer or imap_layer:
                event = pop3_imap_rules.process_pop3_imap_packet(pop3_layer, imap_layer, packet_info)
                if event: return event

        # FTP
        if self.config.is_protocol_enabled("ftp") and "ftp" in layers:
            event = ftp_rules.process_ftp_packet(layers["ftp"], packet_info)
            if event: return event

        # TELNET
        if self.config.is_protocol_enabled("telnet") and "telnet" in layers:
            event = telnet_rules.process_telnet_packet(layers["telnet"], packet_info)
            if event: return event

        # TLS
        if self.config.is_protocol_enabled("tls") and "tls" in layers:
            tls_config = self.config.get("detector.protocols.tls", {})
            min_version = tls_config.get("min_version", "1.2")
            require_sni = tls_config.get("require_sni", False)
            event = tls_rules.process_tls_packet(layers["tls"], packet_info, min_version, require_sni)
            if event: return event
                
        return None
