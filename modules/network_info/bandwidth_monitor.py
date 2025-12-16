"""
Bandwidth monitoring
"""

import psutil
import time
from typing import Dict, List, Optional
from collections import deque
from datetime import datetime
import threading


class BandwidthMonitor:
    """
    Monitor network bandwidth in real-time
    """
    
    def __init__(self, interval: float = 1.0, history_size: int = 60):
        self.interval = interval
        self.history_size = history_size
        self.history = {
            'upload': deque(maxlen=history_size),
            'download': deque(maxlen=history_size),
            'timestamps': deque(maxlen=history_size)
        }
        self.is_monitoring = False
        self.monitor_thread = None
        self.last_stats = None
    
    def start_monitoring(self, interface: Optional[str] = None):
        """
        Start monitoring bandwidth
        
        Args:
            interface: Interface name (None for all interfaces)
        """
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interface,),
            daemon=True
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring bandwidth"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def _monitor_loop(self, interface: Optional[str]):
        """Internal monitoring loop"""
        # Get initial stats
        if interface:
            self.last_stats = psutil.net_io_counters(pernic=True).get(interface)
        else:
            self.last_stats = psutil.net_io_counters()
        
        last_time = time.time()
        
        while self.is_monitoring:
            time.sleep(self.interval)
            
            # Get current stats
            if interface:
                current_stats = psutil.net_io_counters(pernic=True).get(interface)
            else:
                current_stats = psutil.net_io_counters()
            
            if current_stats and self.last_stats:
                current_time = time.time()
                time_delta = current_time - last_time
                
                # Calculate bytes per second
                upload_bps = (current_stats.bytes_sent - self.last_stats.bytes_sent) / time_delta
                download_bps = (current_stats.bytes_recv - self.last_stats.bytes_recv) / time_delta
                
                # Add to history
                self.history['upload'].append(upload_bps)
                self.history['download'].append(download_bps)
                self.history['timestamps'].append(datetime.now())
                
                # Update last stats
                self.last_stats = current_stats
                last_time = current_time
    
    def get_current_bandwidth(self) -> Dict:
        """
        Get current bandwidth usage
        
        Returns:
            Dictionary with current upload/download speeds
        """
        if len(self.history['upload']) > 0:
            return {
                'upload_bps': self.history['upload'][-1],
                'download_bps': self.history['download'][-1],
                'upload_mbps': self.history['upload'][-1] / (1024 * 1024),
                'download_mbps': self.history['download'][-1] / (1024 * 1024),
                'timestamp': self.history['timestamps'][-1].isoformat()
            }
        return {
            'upload_bps': 0,
            'download_bps': 0,
            'upload_mbps': 0,
            'download_mbps': 0,
            'timestamp': None
        }
    
    def get_bandwidth_history(self) -> Dict:
        """
        Get bandwidth history
        
        Returns:
            Dictionary with bandwidth history
        """
        return {
            'upload': list(self.history['upload']),
            'download': list(self.history['download']),
            'timestamps': [ts.isoformat() for ts in self.history['timestamps']]
        }
    
    def get_statistics(self) -> Dict:
        """
        Get bandwidth statistics
        
        Returns:
            Dictionary with statistics
        """
        if len(self.history['upload']) == 0:
            return {}
        
        upload_list = list(self.history['upload'])
        download_list = list(self.history['download'])
        
        return {
            'upload': {
                'current_bps': upload_list[-1],
                'current_mbps': upload_list[-1] / (1024 * 1024),
                'average_bps': sum(upload_list) / len(upload_list),
                'average_mbps': (sum(upload_list) / len(upload_list)) / (1024 * 1024),
                'peak_bps': max(upload_list),
                'peak_mbps': max(upload_list) / (1024 * 1024),
                'total_bytes': sum(upload_list) * self.interval
            },
            'download': {
                'current_bps': download_list[-1],
                'current_mbps': download_list[-1] / (1024 * 1024),
                'average_bps': sum(download_list) / len(download_list),
                'average_mbps': (sum(download_list) / len(download_list)) / (1024 * 1024),
                'peak_bps': max(download_list),
                'peak_mbps': max(download_list) / (1024 * 1024),
                'total_bytes': sum(download_list) * self.interval
            }
        }
    
    def clear_history(self):
        """Clear bandwidth history"""
        self.history['upload'].clear()
        self.history['download'].clear()
        self.history['timestamps'].clear()
    
    @staticmethod
    def get_interface_bandwidth(interface: str, duration: float = 1.0) -> Dict:
        """
        Get bandwidth for an interface over a duration
        
        Args:
            interface: Interface name
            duration: Duration in seconds
        
        Returns:
            Dictionary with bandwidth measurements
        """
        # Get initial stats
        net_io = psutil.net_io_counters(pernic=True)
        if interface not in net_io:
            return {}
        
        initial_stats = net_io[interface]
        time.sleep(duration)
        
        # Get final stats
        net_io = psutil.net_io_counters(pernic=True)
        final_stats = net_io[interface]
        
        # Calculate bandwidth
        upload_bps = (final_stats.bytes_sent - initial_stats.bytes_sent) / duration
        download_bps = (final_stats.bytes_recv - initial_stats.bytes_recv) / duration
        
        return {
            'interface': interface,
            'upload_bps': upload_bps,
            'download_bps': download_bps,
            'upload_mbps': upload_bps / (1024 * 1024),
            'download_mbps': download_bps / (1024 * 1024),
            'duration': duration
        }
