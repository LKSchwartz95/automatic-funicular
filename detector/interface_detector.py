#!/usr/bin/env python3
"""
Network Interface Detection Utility

This module provides functionality to automatically detect the best network interface
for packet capture, prioritizing active interfaces with internet connectivity.
"""

import subprocess
import re
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class InterfaceDetector:
    """Detects and manages network interfaces for packet capture."""
    
    def __init__(self, tshark_path: str):
        self.tshark_path = tshark_path
        
    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """Get list of available network interfaces from tshark."""
        try:
            result = subprocess.run(
                [self.tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get interfaces: {result.stderr}")
                return []
                
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                # Parse tshark -D output format: "5. \Device\NPF_{...} (Wi-Fi)"
                match = re.match(r'(\d+)\.\s+(.+?)\s+\((.+?)\)', line)
                if match:
                    interfaces.append({
                        'number': match.group(1),
                        'device': match.group(2),
                        'name': match.group(3)
                    })
                    
            return interfaces
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout getting network interfaces")
            return []
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []
    
    def get_active_interfaces(self) -> List[Dict[str, str]]:
        """Get list of active network interfaces using netsh."""
        try:
            # Get active network adapters
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Failed to get active interfaces: {result.stderr}")
                return []
                
            active_interfaces = []
            lines = result.stdout.strip().split('\n')
            
            # Skip header lines
            for line in lines[3:]:  # Skip first 3 header lines
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        state = parts[0]
                        name = ' '.join(parts[3:])  # Name might contain spaces
                        
                        if state == "Enabled":
                            active_interfaces.append({
                                'name': name,
                                'state': state
                            })
                            
            return active_interfaces
            
        except subprocess.TimeoutExpired:
            logger.warning("Timeout getting active interfaces")
            return []
        except Exception as e:
            logger.warning(f"Error getting active interfaces: {e}")
            return []
    
    def find_best_interface(self, preferred_interface: Optional[str] = None) -> Optional[str]:
        """
        Find the best network interface for packet capture.
        
        Priority:
        1. Preferred interface (if specified and available)
        2. Wi-Fi interface (if active)
        3. Ethernet interface (if active)
        4. First active interface
        5. First available interface
        """
        available_interfaces = self.get_available_interfaces()
        active_interfaces = self.get_active_interfaces()
        
        if not available_interfaces:
            logger.error("No network interfaces available")
            return None
            
        # Create lookup for active interfaces
        active_names = {iface['name'] for iface in active_interfaces}
        
        logger.info(f"Available interfaces: {[iface['name'] for iface in available_interfaces]}")
        logger.info(f"Active interfaces: {list(active_names)}")
        
        # 1. Check preferred interface
        if preferred_interface:
            for iface in available_interfaces:
                if iface['name'] == preferred_interface:
                    logger.info(f"Using preferred interface: {preferred_interface}")
                    return preferred_interface
            logger.warning(f"Preferred interface '{preferred_interface}' not found")
        
        # 2. Look for Wi-Fi interface (active)
        for iface in available_interfaces:
            if iface['name'] in ['Wi-Fi', 'WiFi', 'Wireless', 'WLAN'] and iface['name'] in active_names:
                logger.info(f"Using active Wi-Fi interface: {iface['name']}")
                return iface['name']
        
        # 3. Look for Ethernet interface (active)
        for iface in available_interfaces:
            if iface['name'] in ['Ethernet', 'Local Area Connection', 'LAN'] and iface['name'] in active_names:
                logger.info(f"Using active Ethernet interface: {iface['name']}")
                return iface['name']
        
        # 4. Use first active interface
        for iface in available_interfaces:
            if iface['name'] in active_names:
                logger.info(f"Using first active interface: {iface['name']}")
                return iface['name']
        
        # 5. Fallback to first available interface
        logger.warning(f"No active interfaces found, using first available: {available_interfaces[0]['name']}")
        return available_interfaces[0]['name']
    
    def test_interface(self, interface_name: str) -> bool:
        """Test if an interface can capture packets."""
        try:
            # Try to capture 1 packet with a 5-second timeout
            result = subprocess.run(
                [self.tshark_path, "-i", interface_name, "-c", "1", "-T", "json"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.info(f"Interface '{interface_name}' test successful")
                return True
            else:
                logger.warning(f"Interface '{interface_name}' test failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Interface '{interface_name}' test timeout")
            return False
        except Exception as e:
            logger.warning(f"Interface '{interface_name}' test error: {e}")
            return False
