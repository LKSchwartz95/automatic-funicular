import subprocess
import json
import ipaddress
import hashlib
import logging
from typing import Dict, Any, List, Optional, Generator
from datetime import datetime

from .event_model import Event
from .config import ConfigLoader

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
        
        cmd = [
            detector_config["tshark_path"],
            "-i", detector_config["interface"],
            "-l",  # line-buffered
            "-T", "json",
            "-Y", "tcp",  # display filter
            "-n",  # disable name resolution for performance
            "-o", "tcp.desegment_tcp_streams:true",
            "-o", "http.desegment_body:true",
            "-o", "http.tls.port:443",
        ]
        
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

    def _parse_headers(self, fields: List[Dict[str, Any]]) -> Dict[str, str]:
        """Parse HTTP headers from tshark fields."""
        headers = {}
        for field in fields:
            if not isinstance(field, dict):
                continue
                
            name = field.get("name", "")
            if not name.lower().startswith("http/"):
                continue
                
            show = field.get("show", "")
            if not show:
                continue
                
            # Handle different header formats
            if ":" in show:
                # Format: 'Host: example.com'
                parts = show.split(":", 1)
                if len(parts) == 2:
                    headers[parts[0].strip()] = parts[1].strip()
            else:
                # Direct field like http.host
                field_name = name.split(".")[-1]
                if field_name in ("host", "authorization", "user_agent", "content_type"):
                    headers[field_name.replace("_", "-").title()] = show
                    
        return headers

    def _detect_http_basic_auth(self, headers: Dict[str, str]) -> bool:
        """Detect HTTP Basic Authentication."""
        auth_header = headers.get("Authorization") or headers.get("authorization")
        return isinstance(auth_header, str) and auth_header.startswith("Basic ")

    def _scan_body_for_credentials(self, body: str) -> List[str]:
        """Scan HTTP body for credential keys."""
        found_keys = []
        
        # Form-style key=value scanning
        for part in body.split("&"):
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.lower().strip()
                if key in self.credential_keys and value.strip():
                    found_keys.append(key)
                    
        # JSON-like key scanning
        for key in self.credential_keys:
            token = f'"{key}"'
            if token in body:
                found_keys.append(key)
                
        return found_keys

    def _process_http_packet(self, http_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
        """Process HTTP packet for security events."""
        if not self.config.is_protocol_enabled("http"):
            return None
            
        # Extract basic packet info
        src_ip = packet_info.get("src_ip")
        src_port = packet_info.get("src_port")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        
        if not all([src_ip, src_port, dst_ip, dst_port]):
            return None
            
        # Check if destination is allowlisted
        if self._is_allowlisted(dst_ip):
            return None
            
        # Parse headers
        fields = http_layer.get("http", [])
        if not isinstance(fields, list):
            return None
            
        headers = self._parse_headers(fields)
        host = headers.get("Host")
        
        # Check for Basic Auth
        if self._detect_http_basic_auth(headers):
            return Event.create_http_basic_auth(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                host=host
            )
            
        # Check for credentials in body
        body = None
        file_data = http_layer.get("http.file_data")
        if file_data:
            if isinstance(file_data, list):
                body = "\n".join(file_data)
            else:
                body = str(file_data)
                
        if body and len(body.encode("utf-8")) <= self.max_body_size:
            found_keys = self._scan_body_for_credentials(body)
            if found_keys:
                return Event.create_http_credential_key(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    host=host,
                    keys_found=found_keys,
                    body_snippet=body[:256]
                )
                
        return None

    def _process_smtp_packet(self, smtp_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
        """Process SMTP packet for security events."""
        if not self.config.is_protocol_enabled("smtp"):
            return None
            
        # Extract packet info
        src_ip = packet_info.get("src_ip")
        src_port = packet_info.get("src_port")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        
        if not all([src_ip, src_port, dst_ip, dst_port]):
            return None
            
        # Check if destination is allowlisted
        if self._is_allowlisted(dst_ip):
            return None
            
        # Collect SMTP content
        content_lines = []
        for key, value in smtp_layer.items():
            if isinstance(value, list):
                content_lines.extend(value)
            elif isinstance(value, str):
                content_lines.append(value)
                
        content = "\n".join(content_lines).upper()
        
        # Check for AUTH before STARTTLS
        if "AUTH " in content and "STARTTLS" not in content:
            return Event.create_smtp_no_starttls(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port
            )
            
        return None

    def _process_pop3_imap_packet(self, pop3_layer: Dict[str, Any], imap_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
        """Process POP3/IMAP packet for security events."""
        src_ip = packet_info.get("src_ip")
        src_port = packet_info.get("src_port")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        
        if not all([src_ip, src_port, dst_ip, dst_port]):
            return None
            
        # Check if destination is allowlisted
        if self._is_allowlisted(dst_ip):
            return None
            
        # Process POP3
        if pop3_layer and self.config.is_protocol_enabled("imap_pop3"):
            content = "\n".join(str(v) for v in pop3_layer.values() if isinstance(v, str)).upper()
            if ("USER " in content or "PASS " in content) and "STLS" not in content:
                return Event.create_pop3_clear_creds(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
                
        # Process IMAP
        if imap_layer and self.config.is_protocol_enabled("imap_pop3"):
            content = "\n".join(str(v) for v in imap_layer.values() if isinstance(v, str)).upper()
            if " LOGIN " in content and "STARTTLS" not in content:
                return Event.create_imap_clear_login(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
                
        return None

    def _process_ftp_packet(self, ftp_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
        """Process FTP packet for security events."""
        if not self.config.is_protocol_enabled("ftp"):
            return None
            
        src_ip = packet_info.get("src_ip")
        src_port = packet_info.get("src_port")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        
        if not all([src_ip, src_port, dst_ip, dst_port]):
            return None
            
        # Check if destination is allowlisted
        if self._is_allowlisted(dst_ip):
            return None
            
        content = "\n".join(str(v) for v in ftp_layer.values() if isinstance(v, str)).upper()
        if "USER " in content or "PASS " in content:
            return Event.create_ftp_clear_creds(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port
            )
            
        return None

    def _process_telnet_packet(self, telnet_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
        """Process TELNET packet for security events."""
        if not self.config.is_protocol_enabled("telnet"):
            return None
            
        src_ip = packet_info.get("src_ip")
        src_port = packet_info.get("src_port")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        
        if not all([src_ip, src_port, dst_ip, dst_port]):
            return None
            
        # Check if destination is allowlisted
        if self._is_allowlisted(dst_ip):
            return None
            
        content = "\n".join(str(v) for v in telnet_layer.values() if isinstance(v, str)).lower()
        if "login:" in content or "password:" in content:
            return Event.create_telnet_clear_login(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port
            )
            
        return None

    def _extract_packet_info(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract basic packet information from tshark output."""
        try:
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
                    # Parse JSON output
                    data = json.loads(line.strip())
                    
                    # Handle array of packets
                    if isinstance(data, list):
                        packets = data
                    else:
                        packets = [data]
                        
                    # Process each packet
                    for packet in packets:
                        event = self._process_packet(packet)
                        if event:
                            yield event
                            
                except json.JSONDecodeError as e:
                    logger.debug(f"JSON decode error: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            raise
        finally:
            if 'process' in locals():
                process.terminate()
                logger.info("Tshark process terminated")

    def _process_packet(self, packet: Dict[str, Any]) -> Optional[Event]:
        """Process a single packet and return security event if found."""
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return None
            
        layers = packet_info["layers"]
        
        # Process HTTP
        http_layer = layers.get("http")
        if http_layer:
            event = self._process_http_packet(http_layer, packet_info)
            if event:
                return event
                
        # Process SMTP
        smtp_layer = layers.get("smtp")
        if smtp_layer:
            event = self._process_smtp_packet(smtp_layer, packet_info)
            if event:
                return event
                
        # Process POP3/IMAP
        pop3_layer = layers.get("pop") or layers.get("pop3")
        imap_layer = layers.get("imap")
        if pop3_layer or imap_layer:
            event = self._process_pop3_imap_packet(pop3_layer, imap_layer, packet_info)
            if event:
                return event
                
        # Process FTP
        ftp_layer = layers.get("ftp")
        if ftp_layer:
            event = self._process_ftp_packet(ftp_layer, packet_info)
            if event:
                return event
                
        # Process TELNET
        telnet_layer = layers.get("telnet")
        if telnet_layer:
            event = self._process_telnet_packet(telnet_layer, packet_info)
            if event:
                return event
                
        return None
