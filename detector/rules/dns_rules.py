"""
DNS security detection rules.

Detects DNS tunneling, suspicious queries, and data exfiltration attempts.
"""

import logging
import re
from typing import Dict, Any, Optional
from datetime import datetime
from ..event_model import Event

logger = logging.getLogger(__name__)


def detect_dns_tunneling(dns_layer: Dict[str, Any]) -> bool:
    """Detect potential DNS tunneling attempts."""
    # Check for unusually long domain names (common in DNS tunneling)
    query_name = dns_layer.get("dns.qry.name", "")
    
    if len(query_name) > 50:  # Normal DNS names are typically much shorter
        return True
    
    # Check for base64-like patterns in domain names
    base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    if re.search(base64_pattern, query_name):
        return True
    
    # Check for suspicious subdomain patterns
    suspicious_patterns = [
        r'[a-z0-9]{20,}\.',  # Long random subdomains
        r'[A-Za-z0-9+/]{10,}\.',  # Base64-like subdomains
        r'tunnel\.',  # Explicit tunneling indicators
        r'exfil\.',  # Exfiltration indicators
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, query_name, re.IGNORECASE):
            return True
    
    return False


def detect_suspicious_dns_queries(dns_layer: Dict[str, Any]) -> bool:
    """Detect suspicious DNS query patterns."""
    query_name = dns_layer.get("dns.qry.name", "").lower()
    query_type = dns_layer.get("dns.qry.type", "")
    
    # Check for suspicious domain patterns
    suspicious_domains = [
        "malware", "virus", "trojan", "backdoor", "keylogger",
        "botnet", "c2", "command", "control", "exfil",
        "tunnel", "bypass", "proxy", "anonymizer"
    ]
    
    for domain in suspicious_domains:
        if domain in query_name:
            return True
    
    # Check for unusual query types
    unusual_types = ["TXT", "CNAME", "MX"]  # These can be used for data exfiltration
    if query_type in unusual_types and len(query_name) > 30:
        return True
    
    # Check for domains with many subdomains (potential tunneling)
    subdomain_count = query_name.count('.')
    if subdomain_count > 5:  # Normal domains rarely have more than 3-4 levels
        return True
    
    return False


def detect_dns_data_exfiltration(dns_layer: Dict[str, Any]) -> bool:
    """Detect potential data exfiltration via DNS."""
    query_name = dns_layer.get("dns.qry.name", "")
    
    # Check for encoded data patterns
    # Base64 encoding (common in DNS tunneling)
    if re.search(r'[A-Za-z0-9+/]{16,}={0,2}', query_name):
        return True
    
    # Hex encoding
    if re.search(r'[0-9a-fA-F]{16,}', query_name):
        return True
    
    # Check for suspicious TLDs used in tunneling
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf"]  # Free TLDs often used for malicious purposes
    for tld in suspicious_tlds:
        if query_name.endswith(tld):
            return True
    
    return False


def process_dns_packet(
    dns_layer: Dict[str, Any], 
    packet_info: Dict[str, Any],
    detect_tunneling: bool = True
) -> Optional[Event]:
    """Process DNS packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
    query_name = dns_layer.get("dns.qry.name", "")
    query_type = dns_layer.get("dns.qry.type", "")
    
    # Check for DNS tunneling
    if detect_tunneling and detect_dns_tunneling(dns_layer):
        return Event(
            ts=packet_info.get("timestamp"),
            severity="HIGH",
            rule="dns.tunneling",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={
                "protocol": "DNS",
                "description": "Potential DNS tunneling detected",
                "query_name": query_name,
                "query_type": query_type,
                "query_length": len(query_name)
            },
            tags=["dns", "tunneling", "exfiltration"]
        )
    
    # Check for suspicious queries
    if detect_suspicious_dns_queries(dns_layer):
        return Event(
            ts=packet_info.get("timestamp"),
            severity="MED",
            rule="dns.suspicious_query",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={
                "protocol": "DNS",
                "description": "Suspicious DNS query detected",
                "query_name": query_name,
                "query_type": query_type
            },
            tags=["dns", "suspicious", "malware"]
        )
    
    # Check for data exfiltration
    if detect_dns_data_exfiltration(dns_layer):
        return Event(
            ts=packet_info.get("timestamp"),
            severity="HIGH",
            rule="dns.data_exfiltration",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={
                "protocol": "DNS",
                "description": "Potential data exfiltration via DNS",
                "query_name": query_name,
                "query_type": query_type
            },
            tags=["dns", "exfiltration", "data_leak"]
        )
    
    return None
