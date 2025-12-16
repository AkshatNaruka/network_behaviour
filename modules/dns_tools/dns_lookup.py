"""
DNS lookup functionality
"""

import socket
import dns.resolver
import dns.reversename
from typing import List, Dict, Optional


class DNSLookup:
    """
    DNS query and lookup tools
    """
    
    def __init__(self, nameserver: Optional[str] = None):
        self.resolver = dns.resolver.Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
    
    def lookup(self, domain: str, record_type: str = 'A') -> List[str]:
        """
        Perform DNS lookup
        
        Args:
            domain: Domain name to lookup
            record_type: DNS record type (A, AAAA, MX, NS, TXT, etc.)
        
        Returns:
            List of DNS records
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception as e:
            return [f"Error: {str(e)}"]
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup
        
        Args:
            ip: IP address
        
        Returns:
            Hostname or None
        """
        try:
            addr = dns.reversename.from_address(ip)
            hostname = str(self.resolver.resolve(addr, 'PTR')[0])
            return hostname.rstrip('.')
        except Exception:
            return None
    
    def get_all_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Get all common DNS records for a domain
        
        Args:
            domain: Domain name
        
        Returns:
            Dictionary with all record types
        """
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        records = {}
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                records[record_type] = []
        
        return records
    
    def get_mx_records(self, domain: str) -> List[Dict]:
        """
        Get MX records with priority
        
        Args:
            domain: Domain name
        
        Returns:
            List of MX records with priority
        """
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            mx_records.sort(key=lambda x: x['priority'])
            return mx_records
        except Exception:
            return []
    
    def get_nameservers(self, domain: str) -> List[str]:
        """
        Get nameservers for a domain
        
        Args:
            domain: Domain name
        
        Returns:
            List of nameservers
        """
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata).rstrip('.') for rdata in answers]
        except Exception:
            return []
    
    def get_txt_records(self, domain: str) -> List[str]:
        """
        Get TXT records
        
        Args:
            domain: Domain name
        
        Returns:
            List of TXT records
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    def dns_trace(self, domain: str) -> List[Dict]:
        """
        Trace DNS resolution path
        
        Args:
            domain: Domain name
        
        Returns:
            List of DNS servers in resolution path
        """
        trace = []
        try:
            # Start with root servers
            current_domain = domain
            parts = domain.split('.')
            
            for i in range(len(parts)):
                subdomain = '.'.join(parts[i:])
                if subdomain:
                    ns_list = self.get_nameservers(subdomain)
                    if ns_list:
                        trace.append({
                            'domain': subdomain,
                            'nameservers': ns_list
                        })
        except Exception:
            pass
        
        return trace
    
    def check_dnssec(self, domain: str) -> bool:
        """
        Check if DNSSEC is enabled for domain
        
        Args:
            domain: Domain name
        
        Returns:
            True if DNSSEC is enabled
        """
        try:
            answers = self.resolver.resolve(domain, 'DNSKEY')
            return len(answers) > 0
        except Exception:
            return False
    
    def get_soa_record(self, domain: str) -> Optional[Dict]:
        """
        Get SOA (Start of Authority) record
        
        Args:
            domain: Domain name
        
        Returns:
            Dictionary with SOA information
        """
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            if answers:
                soa = answers[0]
                return {
                    'mname': str(soa.mname).rstrip('.'),
                    'rname': str(soa.rname).rstrip('.'),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum
                }
        except Exception:
            pass
        return None
    
    def zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        """
        Attempt DNS zone transfer (AXFR)
        
        Args:
            domain: Domain name
            nameserver: Nameserver to query
        
        Returns:
            List of zone records
        """
        try:
            import dns.zone
            import dns.query
            
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name} {rdataset.ttl} {dns.rdataclass.to_text(rdataset.rdclass)} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
            return records
        except Exception as e:
            return [f"Zone transfer failed: {str(e)}"]
