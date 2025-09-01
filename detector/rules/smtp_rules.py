from typing import Dict, Any, Optional

from ..event_model import Event


def process_smtp_packet(smtp_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
    """Process SMTP packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
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
