import socket
import random

from dns import *
import dns

dns_cache = dict()

class DomainResolver:
    """
    Resolves domains to ip addresses. Can use DNS over TLS or plain DNS.
    """
    # TODO: DOH / DOQ

    @staticmethod
    def resolve_plain(domain: str) -> str:
        """
        Resolves the given domain to an ip address using the system's DNS resolver.
        """
        if domain.startswith('['):
            return domain.strip('[]')
        return socket.gethostbyname(domain)

    @staticmethod
    def resolve_over_dot(domain: str, dns_resolver: str) -> str:
        """
        Resolves the given domain to an ip address using DNS over TLS on the given DNS resolver.
        :param domain: domain name to resolve
        :param dns_resolver: ip address of the DNS resolver
        :return: One ip address for the domain or None
        """
        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        if dns_cache.get(domain):
            return dns_cache.get(domain)

        get_ips = lambda response: str(random.choice([[item for item in record.items] for record in response.answer if record.rdtype == dns.rdatatype.A][0]))
        query = dns.message.make_query(domain, dns.rdatatype.A)
        query.flags |= dns.flags.AD
        query.find_rrset(query.additional, dns.name.root, 65535,
                         dns.rdatatype.OPT, create=True, force_unique=True)
        is_dot_ip = all(map(lambda x: x.isnumeric(), dns_resolver.split('.')))
        if is_dot_ip:
            response = dns.query.tls(query, dns_resolver)
        else:
            dot_ip = dns_cache.get(dns_resolver)
            if not dot_ip:
                dot_resp = dns.query.udp(dns.message.make_query(dns_resolver, dns.rdatatype.A), '8.8.8.8')
                dot_ip = get_ips(dot_resp)
                if dot_ip:
                    dns_cache[dns_resolver] = dot_ip
            response = dns.query.tls(query, dot_ip, server_hostname=dns_resolver)

        if response.rcode() != dns.rcode.NOERROR:
            return None

        # filter ipv4 answer
        ips = get_ips(response)
#        for record in response.answer:
#            if record.rdtype == dns.rdatatype.A:
#                for item in record.items:
#                    ips.append(str(item.address))
        #if len(ips) > 0:
        if ips:
            dns_cache[domain] = ips
            return ips
        else:
            # read CNAME hostnames from answer
            for record in response.answer:
                if record.rdtype == dns.rdatatype.CNAME:
                    for item in record.items:
                        return DomainResolver.resolve_over_dot(str(item.target), dns_resolver)
            return None
