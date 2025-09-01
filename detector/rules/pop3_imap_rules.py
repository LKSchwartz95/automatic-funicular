from typing import Dict, Any, Optional

from ..event_model import Event


def process_pop3_imap_packet(
    pop3_layer: Optional[Dict[str, Any]], 
    imap_layer: Optional[Dict[str, Any]], 
    packet_info: Dict[str, Any]
) -> Optional[Event]:
    """Process POP3/IMAP packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
    # Process POP3
    if pop3_layer:
        content = "\n".join(str(v) for v in pop3_layer.values() if isinstance(v, str)).upper()
        if ("USER " in content or "PASS " in content) and "STLS" not in content:
            return Event.create_pop3_clear_creds(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port
            )
            
    # Process IMAP
    if imap_layer:
        content = "\n".join(str(v) for v in imap_layer.values() if isinstance(v, str)).upper()
        if " LOGIN " in content and "STARTTLS" not in content:
            return Event.create_imap_clear_login(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port
            )
            
    return None
