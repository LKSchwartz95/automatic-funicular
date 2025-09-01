"""
SMB (Server Message Block) security detection rules.

Detects plaintext authentication, weak encryption, and suspicious SMB activity.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from ..event_model import Event

logger = logging.getLogger(__name__)


def detect_smb_plaintext_auth(smb_layer: Dict[str, Any]) -> bool:
    """Detect if SMB authentication is in plaintext."""
    # Check for NTLM authentication without encryption
    smb_header = smb_layer.get("SMB Header", {})
    smb_cmd = smb_header.get("smb.cmd")
    
    # SMB command 0x73 is Session Setup AndX
    if smb_cmd == "0x73":
        # Check if it's a response (bit 0 set means response)
        smb_flags = smb_header.get("smb.flags", "0x00")
        is_response = int(smb_flags, 16) & 0x80
        
        if is_response:
            # Check for NTLM authentication
            smb_data = smb_layer.get("smb.data", "")
            if isinstance(smb_data, list):
                smb_data = " ".join(smb_data)
            
            # Look for NTLM indicators
            if "NTLM" in str(smb_data).upper() or "NEGOTIATE" in str(smb_data).upper():
                return True
    
    return False


def detect_smb_weak_encryption(smb_layer: Dict[str, Any]) -> bool:
    """Detect weak SMB encryption or lack of encryption."""
    smb_header = smb_layer.get("SMB Header", {})
    smb_flags2 = smb_header.get("smb.flags2", "0x0000")
    
    # Check if security signatures are disabled
    flags2_value = int(smb_flags2, 16)
    security_signature_required = flags2_value & 0x0004  # Bit 2
    
    # If security signatures are not required, it's a potential security issue
    if not security_signature_required:
        return True
    
    return False


def detect_smb_suspicious_activity(smb_layer: Dict[str, Any]) -> bool:
    """Detect suspicious SMB activity patterns."""
    smb_header = smb_layer.get("SMB Header", {})
    smb_cmd = smb_header.get("smb.cmd")
    
    # Check for potentially suspicious commands
    suspicious_commands = {
        "0x2e",  # Read AndX
        "0x2f",  # Write AndX
        "0x0a",  # Open AndX
        "0x0c",  # Close
    }
    
    if smb_cmd in suspicious_commands:
        # Check for access to sensitive files
        smb_data = smb_layer.get("smb.data", "")
        if isinstance(smb_data, list):
            smb_data = " ".join(smb_data)
        
        sensitive_patterns = [
            "passwd", "shadow", "config", "secret", "key", "credential",
            "admin", "root", "system", "backup", "dump"
        ]
        
        data_str = str(smb_data).lower()
        for pattern in sensitive_patterns:
            if pattern in data_str:
                return True
    
    return False


def process_smb_packet(
    smb_layer: Dict[str, Any], 
    packet_info: Dict[str, Any],
    detect_plaintext_auth: bool = True
) -> Optional[Event]:
    """Process SMB packet for security events."""
    src_ip = packet_info.get("src_ip")
    src_port = packet_info.get("src_port")
    dst_ip = packet_info.get("dst_ip")
    dst_port = packet_info.get("dst_port")
    
    # Check for plaintext authentication
    if detect_plaintext_auth and detect_smb_plaintext_auth(smb_layer):
        return Event(
            ts=packet_info.get("timestamp"),
            severity="HIGH",
            rule="smb.plaintext_auth",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={
                "protocol": "SMB",
                "description": "Plaintext SMB authentication detected",
                "smb_cmd": smb_layer.get("SMB Header", {}).get("smb.cmd", "unknown")
            },
            tags=["smb", "authentication", "plaintext"]
        )
    
    # Check for weak encryption
    if detect_smb_weak_encryption(smb_layer):
        return Event(
            ts=packet_info.get("timestamp"),
            severity="MED",
            rule="smb.weak_encryption",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={
                "protocol": "SMB",
                "description": "SMB without security signatures detected",
                "smb_cmd": smb_layer.get("SMB Header", {}).get("smb.cmd", "unknown")
            },
            tags=["smb", "encryption", "security"]
        )
    
    # Check for suspicious activity
    if detect_smb_suspicious_activity(smb_layer):
        return Event(
            ts=packet_info.get("timestamp"),
            severity="MED",
            rule="smb.suspicious_activity",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={
                "protocol": "SMB",
                "description": "Suspicious SMB file access detected",
                "smb_cmd": smb_layer.get("SMB Header", {}).get("smb.cmd", "unknown")
            },
            tags=["smb", "suspicious", "file_access"]
        )
    
    return None
