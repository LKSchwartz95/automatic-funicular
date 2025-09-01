from typing import Dict, Any, Optional

from ..event_model import Event


def process_telnet_packet(telnet_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
    """Process TELNET packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
    content = "\n".join(str(v) for v in telnet_layer.values() if isinstance(v, str)).lower()
    if "login:" in content or "password:" in content:
        return Event.create_telnet_clear_login(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port
        )
        
    return None
