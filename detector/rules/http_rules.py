from typing import Dict, Any, List, Optional

from ..event_model import Event


def parse_headers(fields: List[Dict[str, Any]]) -> Dict[str, str]:
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


def detect_http_basic_auth(headers: Dict[str, str]) -> bool:
    """Detect HTTP Basic Authentication."""
    auth_header = headers.get("Authorization") or headers.get("authorization")
    return isinstance(auth_header, str) and auth_header.startswith("Basic ")

def scan_body_for_credentials(body: str, credential_keys: set) -> List[str]:
    """Scan HTTP body for credential keys."""
    found_keys = []
    
    # Form-style key=value scanning
    for part in body.split("&"):
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.lower().strip()
            if key in credential_keys and value.strip():
                found_keys.append(key)
                
    # JSON-like key scanning
    for key in credential_keys:
        token = f'"{key}"'
        if token in body:
            found_keys.append(key)
            
    return list(set(found_keys)) # Return unique keys


def process_http_packet(
    http_layer: Dict[str, Any], 
    packet_info: Dict[str, Any],
    credential_keys: set,
    max_body_size: int
) -> Optional[Event]:
    """Process HTTP packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
    # Parse headers
    fields = http_layer.get("http", [])
    if not isinstance(fields, list):
        return None
        
    headers = parse_headers(fields)
    host = headers.get("Host")
    
    # Check for Basic Auth
    if detect_http_basic_auth(headers):
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
            
    if body and len(body.encode("utf-8")) <= max_body_size:
        found_keys = scan_body_for_credentials(body, credential_keys)
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
