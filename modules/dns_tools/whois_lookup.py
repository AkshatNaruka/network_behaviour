"""
WHOIS lookup functionality
"""

import socket
import re
from typing import Dict, Optional
from datetime import datetime


class WhoisLookup:
    """
    WHOIS query functionality
    """
    
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'me': 'whois.nic.me',
        'default': 'whois.iana.org'
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def lookup(self, domain: str) -> str:
        """
        Perform WHOIS lookup
        
        Args:
            domain: Domain name or IP address
        
        Returns:
            WHOIS response string
        """
        # Determine if it's an IP or domain
        if self._is_ip(domain):
            return self._whois_ip(domain)
        else:
            return self._whois_domain(domain)
    
    def _is_ip(self, address: str) -> bool:
        """Check if address is an IP"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def _whois_domain(self, domain: str) -> str:
        """WHOIS lookup for domain"""
        # Get TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return "Invalid domain"
        
        tld = parts[-1].lower()
        whois_server = self.WHOIS_SERVERS.get(tld, self.WHOIS_SERVERS['default'])
        
        # Query WHOIS server
        response = self._query_whois(whois_server, domain)
        
        # Check if we need to follow a referral
        referral_match = re.search(r'Registrar WHOIS Server:\s*(\S+)', response)
        if referral_match:
            referral_server = referral_match.group(1)
            response = self._query_whois(referral_server, domain)
        
        return response
    
    def _whois_ip(self, ip: str) -> str:
        """WHOIS lookup for IP address"""
        # Use ARIN for IP lookups (American Registry)
        whois_server = 'whois.arin.net'
        response = self._query_whois(whois_server, ip)
        
        # Check for referrals to other RIRs
        referral_match = re.search(r'ReferralServer:\s*whois://(\S+)', response)
        if referral_match:
            referral_server = referral_match.group(1)
            response = self._query_whois(referral_server, ip)
        
        return response
    
    def _query_whois(self, server: str, query: str) -> str:
        """
        Query a WHOIS server
        
        Args:
            server: WHOIS server hostname
            query: Query string
        
        Returns:
            WHOIS response
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            sock.send(f"{query}\r\n".encode('utf-8'))
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error querying WHOIS server: {str(e)}"
    
    def parse_whois(self, whois_data: str) -> Dict:
        """
        Parse WHOIS response into structured data
        
        Args:
            whois_data: Raw WHOIS response
        
        Returns:
            Dictionary with parsed WHOIS information
        """
        parsed = {
            'domain': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'registrant': {},
            'admin': {},
            'tech': {}
        }
        
        lines = whois_data.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Domain Name
            if re.match(r'^Domain Name:', line, re.IGNORECASE):
                parsed['domain'] = re.split(r':\s*', line, 1)[1].strip().lower()
            
            # Registrar
            elif re.match(r'^Registrar:', line, re.IGNORECASE):
                parsed['registrar'] = re.split(r':\s*', line, 1)[1].strip()
            
            # Creation Date
            elif re.match(r'^Creation Date:|^Created:', line, re.IGNORECASE):
                date_str = re.split(r':\s*', line, 1)[1].strip()
                parsed['creation_date'] = self._parse_date(date_str)
            
            # Expiration Date
            elif re.match(r'^Expir|^Registry Expiry Date:', line, re.IGNORECASE):
                date_str = re.split(r':\s*', line, 1)[1].strip()
                parsed['expiration_date'] = self._parse_date(date_str)
            
            # Updated Date
            elif re.match(r'^Updated Date:|^Last Updated:', line, re.IGNORECASE):
                date_str = re.split(r':\s*', line, 1)[1].strip()
                parsed['updated_date'] = self._parse_date(date_str)
            
            # Name Servers
            elif re.match(r'^Name Server:', line, re.IGNORECASE):
                ns = re.split(r':\s*', line, 1)[1].strip().lower()
                if ns not in parsed['name_servers']:
                    parsed['name_servers'].append(ns)
            
            # Status
            elif re.match(r'^Domain Status:|^Status:', line, re.IGNORECASE):
                status = re.split(r':\s*', line, 1)[1].strip()
                if status not in parsed['status']:
                    parsed['status'].append(status)
        
        return parsed
    
    def _parse_date(self, date_str: str) -> Optional[str]:
        """Parse date string into ISO format"""
        try:
            # Try common date formats
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d', '%d-%b-%Y', '%Y-%m-%d %H:%M:%S']:
                try:
                    dt = datetime.strptime(date_str.split('.')[0], fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
        except Exception:
            pass
        return date_str
    
    def get_domain_info(self, domain: str) -> Dict:
        """
        Get parsed domain information
        
        Args:
            domain: Domain name
        
        Returns:
            Parsed WHOIS information
        """
        whois_data = self.lookup(domain)
        return self.parse_whois(whois_data)
