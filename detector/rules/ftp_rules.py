from typing import Dict, Any, Optional

from ..event_model import Event


def process_ftp_packet(ftp_layer: Dict[str, Any], packet_info: Dict[str, Any]) -> Optional[Event]:
    """Process FTP packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
    content = "\n".join(str(v) for v in ftp_layer.values() if isinstance(v, str)).upper()
    if "USER " in content or "PASS " in content:
        return Event.create_ftp_clear_creds(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port
        )
        
    return None

