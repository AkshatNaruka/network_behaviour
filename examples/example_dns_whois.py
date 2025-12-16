#!/usr/bin/env python3
"""
Example: DNS lookup and WHOIS queries
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.dns_tools import DNSLookup, WhoisLookup

def main():
    print("🌐 DNS & WHOIS Example")
    print("=" * 50)
    
    # DNS Lookup
    print("\n📡 DNS Lookup")
    dns = DNSLookup()
    
    domain = "google.com"
    print(f"\n🔍 Looking up {domain}...")
    
    # A records
    print("\n  A Records:")
    a_records = dns.lookup(domain, 'A')
    for record in a_records:
        print(f"    {record}")
    
    # MX records
    print("\n  MX Records:")
    mx_records = dns.get_mx_records(domain)
    for record in mx_records:
        print(f"    Priority {record['priority']}: {record['exchange']}")
    
    # NS records
    print("\n  Name Servers:")
    ns_records = dns.get_nameservers(domain)
    for record in ns_records:
        print(f"    {record}")
    
    # All records
    print("\n\n📋 All DNS Records:")
    all_records = dns.get_all_records(domain)
    for record_type, records in all_records.items():
        if records:
            print(f"\n  {record_type}:")
            for record in records[:3]:  # Limit to 3 per type
                print(f"    {record}")
    
    # Reverse DNS
    print("\n\n🔄 Reverse DNS Lookup")
    ip = "8.8.8.8"
    print(f"  IP: {ip}")
    hostname = dns.reverse_lookup(ip)
    if hostname:
        print(f"  Hostname: {hostname}")
    else:
        print("  No PTR record found")
    
    # WHOIS Lookup
    print("\n\n📋 WHOIS Lookup")
    whois = WhoisLookup()
    
    print(f"\n🔍 WHOIS information for {domain}...")
    info = whois.get_domain_info(domain)
    
    if info.get('domain'):
        print(f"  Domain: {info['domain']}")
    if info.get('registrar'):
        print(f"  Registrar: {info['registrar']}")
    if info.get('creation_date'):
        print(f"  Created: {info['creation_date']}")
    if info.get('expiration_date'):
        print(f"  Expires: {info['expiration_date']}")
    if info.get('name_servers'):
        print(f"  Name Servers: {len(info['name_servers'])}")
        for ns in info['name_servers'][:3]:
            print(f"    {ns}")
    
    print("\n✨ Example complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
