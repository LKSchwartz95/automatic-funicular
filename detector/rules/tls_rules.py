from typing import Dict, Any, Optional, List

from ..event_model import Event


def process_tls_packet(tls_layer: Dict[str, Any], packet_info: Dict[str, Any], min_version: str, require_sni: bool) -> Optional[Event]:
    """
    Process a TLS packet for security events, focusing on the ClientHello.
    """
    src_ip = packet_info.get("src_ip")
    dst_ip = packet_info.get("dst_ip")
    src_port = packet_info.get("src_port")
    dst_port = packet_info.get("dst_port")

    # We are interested in the ClientHello message
    handshake_type = tls_layer.get("tls.handshake.type")
    if handshake_type != "1":  # 1 = ClientHello
        return None

    # Check TLS version
    record_version_str = tls_layer.get("tls.record.version")
    if record_version_str:
        try:
            # tshark format is "0x0303" for TLS 1.2
            record_version = float(int(record_version_str, 16)) / 100.0 - 2.0
            min_v_float = float(min_version)
            if record_version < min_v_float:
                return Event(
                    ts=packet_info.get("timestamp"),
                    severity="MED",
                    rule="tls.weak_version",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    context={
                        "protocol": "TLS",
                        "version_detected": f"{record_version:.1f}",
                        "minimum_required": min_version
                    }
                )
        except (ValueError, TypeError):
            pass # Ignore parsing errors

    # Check for Server Name Indication (SNI)
    if require_sni:
        sni = tls_layer.get("tls.handshake.extensions_server_name")
        if not sni:
            return Event(
                ts=packet_info.get("timestamp"),
                severity="LOW",
                rule="tls.missing_sni",
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                context={"protocol": "TLS"}
            )
            
    return None
