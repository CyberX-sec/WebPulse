import os
import sys
import json
import shodan
import socket
import argparse
import requests
import ipaddress
import urllib.parse
import re
import warnings
import threading
import subprocess
import time
import ssl
import hashlib
import base64
from datetime import datetime, timedelta
from pprint import pprint
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import optional dependencies for enhanced features
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dnspython not available. DNS analysis features will be disabled.")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not available. WHOIS features will be disabled.")

# Suppress InsecureRequestWarning for testing purposes
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_comprehensive_dns_records(domain):
    """Get comprehensive DNS records"""
    if not DNS_AVAILABLE:
        return {"error": "dnspython library not available. Install with: pip install dnspython"}
    
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
    
    try:
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception as e:
                records[record_type] = []
                
        # Check for email security records
        try:
            # SPF Record
            spf_record = None
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                if 'v=spf1' in str(record):
                    spf_record = str(record)
                    break
            records['SPF'] = spf_record
        except:
            records['SPF'] = None
            
        # DMARC Record
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    records['DMARC'] = str(record)
                    break
        except:
            records['DMARC'] = None
            
    except Exception as e:
        records['error'] = str(e)
    
    return records


def get_whois_information(domain):
    """Get WHOIS information"""
    if not WHOIS_AVAILABLE:
        return {"error": "python-whois library not available. Install with: pip install python-whois"}
    
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': str(w.creation_date) if w.creation_date else None,
            'expiration_date': str(w.expiration_date) if w.expiration_date else None,
            'name_servers': w.name_servers if w.name_servers else [],
            'emails': w.emails if w.emails else [],
            'organization': w.org if hasattr(w, 'org') and w.org else None,
            'country': w.country if hasattr(w, 'country') and w.country else None,
            'registrant': w.registrant if hasattr(w, 'registrant') and w.registrant else None
        }
    except Exception as e:
        return {'error': str(e)}


def check_certificate_transparency_logs(domain):
    """Check Certificate Transparency logs for additional subdomains"""
    try:
        ct_url = f'https://crt.sh/?q={domain}&output=json'
        response = requests.get(ct_url, timeout=15)
        if response.status_code == 200:
            certificates = response.json()
            subdomains = set()
            for cert in certificates:
                name = cert.get('name_value', '')
                if name and domain in name:
                    # Clean up the subdomain names
                    names = name.split('\n')
                    for n in names:
                        n = n.strip()
                        if n and domain in n and not n.startswith('*'):
                            subdomains.add(n)
            return {
                'total_certificates': len(certificates),
                'discovered_subdomains': list(subdomains)[:50]  # Limit to 50 for readability
            }
    except Exception as e:
        return {'error': str(e)}
    return {'error': 'No data found'}


def check_cloud_provider(ip):
    """Identify cloud service provider"""
    cloud_ranges = {
        'Amazon AWS': [
            '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.192.0.0/10',
            '35.153.0.0/16', '52.0.0.0/8', '54.0.0.0/8'
        ],
        'Google Cloud': [
            '34.0.0.0/8', '35.0.0.0/8', '130.211.0.0/16', '104.154.0.0/16',
            '104.196.0.0/14', '107.167.160.0/19', '107.178.192.0/18'
        ],
        'Microsoft Azure': [
            '13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14', '20.0.0.0/8',
            '40.0.0.0/8', '52.0.0.0/8', '104.0.0.0/8'
        ],
        'Cloudflare': [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18'
        ],
        'DigitalOcean': [
            '104.131.0.0/16', '159.203.0.0/16', '178.62.0.0/16',
            '188.226.0.0/16', '192.241.0.0/16'
        ]
    }
    
    try:
        target_ip = ipaddress.ip_address(ip)
        
        for provider, ranges in cloud_ranges.items():
            for cidr in ranges:
                try:
                    if target_ip in ipaddress.ip_network(cidr):
                        return provider
                except:
                    continue
        
        return 'Unknown/On-Premise'
    except:
        return 'Invalid IP'


def check_web_archive_history(domain):
    """Check Wayback Machine for historical data"""
    try:
        wayback_url = f'http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=10'
        response = requests.get(wayback_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:  # First row is headers
                return {
                    'archived': True,
                    'total_snapshots': len(data) - 1,
                    'oldest_snapshot': data[1][1] if len(data) > 1 else None,
                    'newest_snapshot': data[-1][1] if len(data) > 1 else None,
                    'first_archive_url': f'http://web.archive.org/web/{data[1][1]}/{domain}' if len(data) > 1 else None
                }
        return {'archived': False}
    except Exception as e:
        return {'archived': False, 'error': str(e)}


def check_advanced_cms_detection(domain):
    """Advanced CMS and framework detection"""
    cms_signatures = {
        'WordPress': {
            'headers': ['x-pingback'],
            'content': ['/wp-content/', '/wp-admin/', 'wp-includes', 'wordpress'],
            'meta': ['generator.*wordpress']
        },
        'Drupal': {
            'headers': ['x-drupal'],
            'content': ['/sites/default/', '/modules/', '/themes/', 'drupal'],
            'meta': ['generator.*drupal']
        },
        'Joomla': {
            'headers': [],
            'content': ['/administrator/', '/components/', '/modules/', 'joomla'],
            'meta': ['generator.*joomla']
        },
        'Magento': {
            'headers': [],
            'content': ['/skin/frontend/', '/js/mage/', '/media/catalog/'],
            'meta': []
        },
        'Shopify': {
            'headers': [],
            'content': ['cdn.shopify.com', 'shopify-analytics', 'shopify'],
            'meta': []
        },
        'React': {
            'headers': [],
            'content': ['react', '__react', 'react-dom'],
            'meta': []
        },
        'Angular': {
            'headers': [],
            'content': ['angular', 'ng-app', 'ng-controller'],
            'meta': []
        },
        'Vue.js': {
            'headers': [],
            'content': ['vue.js', 'vue.min.js', 'v-if', 'v-for'],
            'meta': []
        }
    }
    
    detected_technologies = []
    
    try:
        response = requests.get(f'http://{domain}', timeout=10, verify=False)
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for tech, signatures in cms_signatures.items():
            detected = False
            
            # Check headers
            for header_sig in signatures['headers']:
                if any(header_sig in k for k in headers.keys()):
                    detected = True
                    break
            
            # Check content
            if not detected:
                for content_sig in signatures['content']:
                    if content_sig.lower() in content:
                        detected = True
                        break
            
            # Check meta tags
            if not detected:
                for meta_sig in signatures['meta']:
                    if re.search(meta_sig, content, re.IGNORECASE):
                        detected = True
                        break
            
            if detected:
                detected_technologies.append(tech)
                
    except Exception as e:
        return {'error': str(e)}
    
    return detected_technologies


def check_api_endpoints(domain):
    """Discover potential API endpoints"""
    api_paths = [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
        '/swagger', '/docs', '/openapi.json', '/api-docs',
        '/.well-known/openid_configuration', '/manifest.json',
        '/sitemap.xml', '/robots.txt', '/security.txt'
    ]
    
    discovered_apis = []
    
    for path in api_paths:
        try:
            url = f'http://{domain}{path}'
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code in [200, 201, 301, 302, 401, 403]:
                content_type = response.headers.get('content-type', '')
                discovered_apis.append({
                    'endpoint': path,
                    'status': response.status_code,
                    'content_type': content_type,
                    'size': len(response.content),
                    'accessible': response.status_code in [200, 201]
                })
        except:
            continue
    
    return discovered_apis


def analyze_http_response(url, headers, content, status_code):
    """Analyze HTTP response for potential vulnerabilities"""
    findings = []
    
    # Check for security headers
    security_headers = {
        'x-frame-options': 'Missing X-Frame-Options header (Clickjacking vulnerability)',
        'x-content-type-options': 'Missing X-Content-Type-Options header',
        'x-xss-protection': 'Missing X-XSS-Protection header',
        'strict-transport-security': 'Missing HSTS header',
        'content-security-policy': 'Missing Content-Security-Policy header'
    }
    
    for header, message in security_headers.items():
        if header not in [h.lower() for h in headers.keys()]:
            findings.append({
                'type': 'Missing Security Header',
                'severity': 'Medium',
                'description': message
            })
    
    # Check for server information disclosure
    if 'server' in headers:
        findings.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'description': f'Server header reveals: {headers["server"]}'
        })
    
    # Check for common vulnerabilities in content
    if content:
        # SQL injection patterns
        sql_patterns = [
            r'sql syntax.*mysql',
            r'warning.*mysql_.*',
            r'valid mysql result',
            r'postgresql.*error',
            r'warning.*postgresql',
            r'oracle database error',
            r'microsoft jet database',
            r'odbc.*driver'
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'Potential SQL Injection',
                    'severity': 'High',
                    'description': 'Database error messages found in response'
                })
                break
        
        # Directory listing
        if 'index of /' in content.lower():
            findings.append({
                'type': 'Directory Listing',
                'severity': 'Medium',
                'description': 'Directory listing is enabled'
            })
        
        # Backup files
        backup_patterns = [
            r'\.bak\b',
            r'\.backup\b',
            r'\.old\b',
            r'\.orig\b',
            r'\.tmp\b'
        ]
        
        for pattern in backup_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'Backup Files',
                    'severity': 'Medium',
                    'description': 'Potential backup files found'
                })
                break
    
    return findings


def extract_version_from_server_header(server_header):
    """Extract server name and version from server header"""
    # Common patterns for server headers
    patterns = [
        (r'Apache/([0-9.]+)', 'Apache'),
        (r'nginx/([0-9.]+)', 'nginx'),
        (r'Microsoft-IIS/([0-9.]+)', 'IIS'),
        (r'LiteSpeed/([0-9.]+)', 'LiteSpeed'),
        (r'Tomcat/([0-9.]+)', 'Tomcat'),
        (r'PHP/([0-9.]+)', 'PHP')
    ]
    
    for pattern, name in patterns:
        match = re.search(pattern, server_header, re.IGNORECASE)
        if match:
            return name, match.group(1)
    
    # Generic extraction
    parts = server_header.split('/')
    if len(parts) >= 2:
        return parts[0], parts[1].split()[0]
    
    return server_header, 'Unknown'


def check_for_cve(product, version):
    """Basic CVE checking (simplified implementation)"""
    # This is a simplified implementation
    # In a real-world scenario, you would query actual CVE databases
    
    known_vulnerabilities = {
        'Apache': {
            '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
            '2.4.48': ['CVE-2021-34798'],
            '2.2.34': ['CVE-2017-15710']
        },
        'nginx': {
            '1.20.0': ['CVE-2021-23017'],
            '1.18.0': ['CVE-2020-11724']
        },
        'PHP': {
            '7.4.21': ['CVE-2021-21705'],
            '8.0.8': ['CVE-2021-21704']
        }
    }
    
    if product in known_vulnerabilities:
        if version in known_vulnerabilities[product]:
            return known_vulnerabilities[product][version]
    
    return []


def perform_active_web_scan(domain):
    """Perform comprehensive active web scanning"""
    findings = {}
    
    try:
        # Basic HTTP request to gather information
        url = f"http://{domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        findings['http_status'] = response.status_code
        findings['response_headers'] = dict(response.headers)
        findings['response_size'] = len(response.content)
        
        # Check for common directories and files
        common_paths = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/config.php',
            '/backup', '/test', '/dev', '/api'
        ]
        
        findings['discovered_paths'] = []
        for path in common_paths:
            try:
                test_url = f"{url}{path}"
                test_response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                if test_response.status_code in [200, 301, 302, 403]:
                    findings['discovered_paths'].append({
                        'path': path,
                        'status': test_response.status_code,
                        'size': len(test_response.content)
                    })
            except:
                continue
        
        # Check for HTTPS
        try:
            https_url = f"https://{domain}"
            https_response = requests.get(https_url, headers=headers, timeout=10, verify=False)
            findings['https_available'] = True
            findings['https_status'] = https_response.status_code
        except:
            findings['https_available'] = False
        
        # Basic port scanning
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        findings['open_ports'] = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                result = sock.connect_ex((domain, port))
                if result == 0:
                    findings['open_ports'].append(port)
                sock.close()
            except:
                sock.close()
                continue
        
    except Exception as e:
        findings['error'] = str(e)
    
    return findings


def print_banner(title):
    """Print a banner to separate sections of output"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def print_section(title):
    """Print a section header"""
    print(f"\n--- {title} ---\n")


def get_user_input(prompt, default=None):
    """Get input from user with default value"""
    if default:
        user_input = input(f"{prompt} [{default}]: ")
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ")


def get_yes_no_input(prompt, default="y"):
    """Get yes/no input from user"""
    valid = {"y": True, "yes": True, "n": False, "no": False}
    if default is None:
        prompt_text = f"{prompt} (y/n): "
    elif default.lower() == "y":
        prompt_text = f"{prompt} (Y/n): "
    elif default.lower() == "n":
        prompt_text = f"{prompt} (y/N): "
    else:
        raise ValueError("Invalid default value for yes/no question")
        
    while True:
        choice = input(prompt_text).lower()
        if choice == '':
            return valid[default.lower()]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'y' or 'n'")


def resolve_domain(domain):
    """Resolve a domain to its IP address"""
    try:
        print(f"Resolving domain {domain}...")
        ip = socket.gethostbyname(domain)
        print(f"Domain {domain} resolves to IP: {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Could not resolve domain {domain}")
        return None


def extract_hostname(url):
    """Extract hostname from URL"""
    # Add http:// if no scheme is present
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return urllib.parse.urlparse(url).netloc.split(':')[0]


def is_ip_address(domain_or_ip):
    """Check if the input is an IP address"""
    try:
        ipaddress.ip_address(domain_or_ip)
        return True
    except ValueError:
        return False


def collect_domain_info(api, domain, ip):
    """Get comprehensive information about a domain and its IP"""
    result = {
        "basic_info": {
            "domain": domain,
            "ip": ip,
            "timestamp": datetime.now().isoformat()
        }
    }
    
    try:
        # Get information about the IP
        host_info = api.host(ip)
        
        # Basic information
        result["host_info"] = {
            "ip": host_info.get('ip_str'),
            "organization": host_info.get('org'),
            "isp": host_info.get('isp'),
            "country": host_info.get('country_name'),
            "last_update": host_info.get('last_update'),
            "asn": host_info.get('asn'),
            "tags": host_info.get('tags', [])
        }
        
        if 'city' in host_info and 'region_code' in host_info:
            result["host_info"]["location"] = {
                "city": host_info.get('city'),
                "region_code": host_info.get('region_code'),
                "country_code": host_info.get('country_code'),
                "latitude": host_info.get('latitude'),
                "longitude": host_info.get('longitude')
            }
        
        # Ports and services
        if 'ports' in host_info and host_info['ports']:
            result["host_info"]["ports"] = host_info['ports']
            
        # Hostnames and domains
        if 'hostnames' in host_info and host_info['hostnames']:
            result["host_info"]["hostnames"] = host_info['hostnames']
            
        if 'domains' in host_info and host_info['domains']:
            result["host_info"]["domains"] = host_info['domains']
        
        # Operating System
        if 'os' in host_info and host_info['os']:
            result["host_info"]["os"] = host_info['os']
            
        # Detailed service information
        if 'data' in host_info and host_info['data']:
            result["services"] = []
            for service in host_info['data']:
                service_info = {
                    "port": service.get('port'),
                    "protocol": service.get('transport')
                }
                
                if 'product' in service:
                    service_info["product"] = service.get('product')
                if 'version' in service:
                    service_info["version"] = service.get('version')
                if 'cpe' in service and service['cpe']:
                    service_info["cpe"] = service['cpe'][0] if isinstance(service['cpe'], list) else service['cpe']
                
                # HTTP specific information
                if 'http' in service:
                    http_info = {}
                    if 'title' in service['http']:
                        http_info["page_title"] = service['http'].get('title')
                    if 'server' in service['http']:
                        http_info["server"] = service['http'].get('server')
                    if 'html' in service['http']:
                        http_info["html_hash"] = hash(service['http'].get('html'))  # Just store the hash to save space
                    if 'robots_hash' in service['http']:
                        http_info["robots_txt_hash"] = service['http'].get('robots_hash')
                    if 'sitemap_hash' in service['http']:
                        http_info["sitemap_hash"] = service['http'].get('sitemap_hash')
                    if 'components' in service['http']:
                        http_info["components"] = service['http'].get('components', {})
                    if 'host' in service['http']:
                        http_info["host_header"] = service['http'].get('host')
                    if 'location' in service['http']:
                        http_info["redirect_location"] = service['http'].get('location')
                    if 'html_hash' in service['http']:
                        http_info["html_hash"] = service['http'].get('html_hash')
                    
                    # Security headers
                    headers = {}
                    if 'headers' in service['http']:
                        for header in service['http']['headers']:
                            headers[header['name'].lower()] = header['value']
                        
                        security_headers = {
                            "content_security_policy": headers.get('content-security-policy'),
                            "strict_transport_security": headers.get('strict-transport-security'),
                            "x_frame_options": headers.get('x-frame-options'),
                            "x_xss_protection": headers.get('x-xss-protection'),
                            "x_content_type_options": headers.get('x-content-type-options'),
                            "referrer_policy": headers.get('referrer-policy')
                        }
                        http_info["security_headers"] = {k: v for k, v in security_headers.items() if v is not None}
                        
                        # Check for CORS configuration
                        cors_headers = {
                            "access_control_allow_origin": headers.get('access-control-allow-origin'),
                            "access_control_allow_methods": headers.get('access-control-allow-methods'),
                            "access_control_allow_headers": headers.get('access-control-allow-headers'),
                            "access_control_expose_headers": headers.get('access-control-expose-headers')
                        }
                        cors_config = {k: v for k, v in cors_headers.items() if v is not None}
                        if cors_config:
                            http_info["cors_config"] = cors_config
                    
                    # Response status code
                    if 'status' in service['http']:
                        http_info["status_code"] = service['http'].get('status')
                        
                    service_info["http"] = http_info
                
                # Certificate information for HTTPS
                if 'ssl' in service:
                    ssl_info = {}
                    if 'cert' in service['ssl']:
                        cert = service['ssl']['cert']
                        ssl_info['subject'] = cert.get('subject', {})
                        ssl_info['issuer'] = cert.get('issuer', {})
                        ssl_info['version'] = cert.get('version')
                        ssl_info['serial'] = cert.get('serial')
                        ssl_info['valid_from'] = cert.get('issued')
                        ssl_info['valid_to'] = cert.get('expires')
                        
                        if 'extensions' in cert:
                            if 'subjectAltName' in cert['extensions']:
                                ssl_info['alternative_names'] = cert['extensions']['subjectAltName'].split(', ')
                            
                            if 'authorityKeyIdentifier' in cert['extensions']:
                                ssl_info['authority_key_id'] = cert['extensions']['authorityKeyIdentifier']
                    
                    if 'versions' in service['ssl']:
                        ssl_info['protocol_versions'] = service['ssl'].get('versions', [])
                    if 'cipher' in service['ssl']:
                        ssl_info['cipher'] = service['ssl'].get('cipher', {})
                    if 'dhparams' in service['ssl']:
                        ssl_info['dhparams'] = service['ssl'].get('dhparams', {})
                    
                    service_info["ssl"] = ssl_info
                
                result["services"].append(service_info)
        
        print_section("Host Information Collected")
        print(f"Collected basic host information for {domain} ({ip})")
        return result
    
    except shodan.APIError as e:
        print(f"Error retrieving host information: {e}")
        return result


def collect_related_hosts(api, domain, result_limit=5):
    """Search for other hosts related to this domain"""
    result = {"related_hosts": []}
    
    try:
        # Try different queries to find related information
        queries = [
            f'hostname:"{domain}"',  # Exact hostname match
            f'ssl:"{domain}"',       # Domain in SSL certificates
            f'http.html:"{domain}"', # Domain in HTTP content
            f'http.title:"{domain}"' # Domain in page titles
        ]
        
        # If domain has www, try without it and vice versa
        alt_domain = domain
        if domain.startswith('www.'):
            alt_domain = domain[4:]  # Remove www.
            queries.append(f'hostname:"{alt_domain}"')
        else:
            queries.append(f'hostname:"www.{domain}"')
        
        for query in queries:
            try:
                print_section(f"Searching: {query}")
                search_results = api.search(query, limit=result_limit)
                
                if search_results['total'] == 0:
                    print(f"No results found for query: {query}")
                    continue
                    
                print(f"Found {search_results['total']} related hosts. Processing first {result_limit}...")
                
                for result_item in search_results['matches']:
                    host_data = {
                        "ip": result_item.get('ip_str'),
                        "port": result_item.get('port'),
                        "organization": result_item.get('org'),
                        "hostnames": result_item.get('hostnames', []),
                        "domain": result_item.get('domains', []),
                        "query": query,
                        "timestamp": result_item.get('timestamp')
                    }
                    
                    # Get HTTP info if available
                    if 'http' in result_item:
                        http_data = {}
                        if 'title' in result_item['http']:
                            http_data['title'] = result_item['http']['title']
                        if 'server' in result_item['http']:
                            http_data['server'] = result_item['http']['server']
                        if 'status' in result_item['http']:
                            http_data['status'] = result_item['http']['status']
                        if 'location' in result_item['http']:
                            http_data['redirect'] = result_item['http']['location']
                        if http_data:
                            host_data['http'] = http_data
                    
                    result["related_hosts"].append(host_data)
            
            except shodan.APIError as e:
                print(f"Error executing query '{query}': {e}")
        
        print_section("Related Hosts Collected")
        print(f"Collected {len(result['related_hosts'])} related hosts")
        return result
    
    except Exception as e:
        print(f"Error searching for related hosts: {e}")
        return result


def collect_ssl_information(api, domain, result_limit=5):
    """Get SSL certificate information for the domain"""
    result = {"ssl_certificates": []}
    
    try:
        # Search for SSL certificates for this domain
        query = f'ssl:"{domain}"'
        print_section(f"Searching for SSL certificates: {query}")
        search_results = api.search(query, limit=result_limit)
        
        if search_results['total'] == 0:
            print(f"No SSL certificate information found for {domain}")
            return result
            
        print(f"Found {search_results['total']} SSL certificates. Processing first {result_limit}...")
        
        for result_item in search_results['matches']:
            cert_data = {
                "ip": result_item.get('ip_str'),
                "port": result_item.get('port'),
                "hostnames": result_item.get('hostnames', []),
                "timestamp": result_item.get('timestamp')
            }
            
            if 'ssl' in result_item and 'cert' in result_item['ssl']:
                cert = result_item['ssl']['cert']
                cert_details = {}
                
                if 'subject' in cert:
                    cert_details["subject"] = {
                        "common_name": cert['subject'].get('CN'),
                        "organization": cert['subject'].get('O'),
                        "organizational_unit": cert['subject'].get('OU')
                    }
                
                if 'issuer' in cert:
                    cert_details["issuer"] = {
                        "common_name": cert['issuer'].get('CN'),
                        "organization": cert['issuer'].get('O')
                    }
                
                cert_details["valid_from"] = cert.get('issued')
                cert_details["valid_until"] = cert.get('expires')
                cert_details["serial_number"] = cert.get('serial')
                cert_details["version"] = cert.get('version')
                
                if 'extensions' in cert:
                    cert_details["extensions"] = {}
                    
                    if 'subjectAltName' in cert['extensions']:
                        cert_details["extensions"]["subject_alt_names"] = cert['extensions']['subjectAltName'].split(', ')
                    
                    if 'keyUsage' in cert['extensions']:
                        cert_details["extensions"]["key_usage"] = cert['extensions']['keyUsage']
                    
                    if 'extendedKeyUsage' in cert['extensions']:
                        cert_details["extensions"]["extended_key_usage"] = cert['extensions']['extendedKeyUsage']
                
                # SSL/TLS protocol info
                if 'versions' in result_item['ssl']:
                    cert_details["tls_versions"] = result_item['ssl']['versions']
                
                # Cipher info
                if 'cipher' in result_item['ssl']:
                    cert_details["cipher"] = {
                        "bits": result_item['ssl']['cipher'].get('bits'),
                        "name": result_item['ssl']['cipher'].get('name'),
                        "version": result_item['ssl']['cipher'].get('version')
                    }
                
                # Check for weak ciphers or protocols
                weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1']
                if 'versions' in result_item['ssl']:
                    cert_details["security_issues"] = []
                    for protocol in weak_protocols:
                        if protocol in result_item['ssl']['versions']:
                            cert_details["security_issues"].append(f"Weak protocol: {protocol}")
                
                cert_data["details"] = cert_details
            
            result["ssl_certificates"].append(cert_data)
        
        print_section("SSL Certificates Collected")
        print(f"Collected {len(result['ssl_certificates'])} SSL certificates")
        return result
    
    except shodan.APIError as e:
        print(f"Error retrieving SSL information: {e}")
        return result


def collect_web_technologies(api, domain, ip):
    """Detect web technologies used by the target"""
    result = {"web_technologies": []}
    
    try:
        # Search for technologies used on this host
        print_section(f"Searching for web technologies on {domain}")
        
        queries = [
            f'ip:"{ip}" http.component:*',  # Components for the specific IP
            f'hostname:"{domain}" http.component:*'  # Components for the hostname
        ]
        
        for query in queries:
            try:
                search_results = api.search(query, limit=10)
                
                if search_results['total'] == 0:
                    print(f"No web technology information found for query: {query}")
                    continue
                
                print(f"Found {search_results['total']} results with technology information. Processing...")
                
                for result_item in search_results['matches']:
                    tech_data = {
                        "ip": result_item.get('ip_str'),
                        "port": result_item.get('port'),
                        "query": query
                    }
                    
                    if 'http' in result_item and 'components' in result_item['http']:
                        components = {}
                        for comp_name, comp_details in result_item['http']['components'].items():
                            component = {
                                "categories": comp_details.get('categories', []),
                            }
                            if 'version' in comp_details:
                                component['version'] = comp_details['version']
                            
                            components[comp_name] = component
                        
                        tech_data["components"] = components
                        
                        # Categorize technologies
                        categories = {
                            "cms": [],
                            "javascript_frameworks": [],
                            "web_servers": [],
                            "programming_languages": [],
                            "analytics": [],
                            "widgets": [],
                            "security": []
                        }
                        
                        for comp_name, comp_details in result_item['http']['components'].items():
                            for category in comp_details.get('categories', []):
                                category = category.lower()
                                if 'cms' in category:
                                    categories['cms'].append(comp_name)
                                elif any(js in category for js in ['javascript', 'js']):
                                    categories['javascript_frameworks'].append(comp_name)
                                elif any(ws in category for ws in ['web server', 'webserver']):
                                    categories['web_servers'].append(comp_name)
                                elif any(pl in category for pl in ['programming', 'language']):
                                    categories['programming_languages'].append(comp_name)
                                elif 'analytics' in category:
                                    categories['analytics'].append(comp_name)
                                elif 'widget' in category:
                                    categories['widgets'].append(comp_name)
                                elif any(sec in category for sec in ['security', 'captcha', 'firewall']):
                                    categories['security'].append(comp_name)
                        
                        # Filter empty categories
                        tech_data["categories"] = {k: v for k, v in categories.items() if v}
                    
                    result["web_technologies"].append(tech_data)
            
            except shodan.APIError as e:
                print(f"Error executing query '{query}': {e}")
        
        # Deduplicate results
        unique_ips = set()
        filtered_results = []
        for tech in result["web_technologies"]:
            ip_port = f"{tech['ip']}:{tech['port']}"
            if ip_port not in unique_ips:
                unique_ips.add(ip_port)
                filtered_results.append(tech)
        
        result["web_technologies"] = filtered_results
        
        print_section("Web Technologies Collected")
        print(f"Collected information about {len(result['web_technologies'])} web technology instances")
        return result
    
    except Exception as e:
        print(f"Error detecting web technologies: {e}")
        return result


def collect_security_headers(api, domain, ip, result_limit=5):
    """Analyze HTTP security headers"""
    result = {"security_headers": {"analysis": {}, "headers": []}}
    
    try:
        # Search for HTTP headers
        print_section(f"Analyzing security headers for {domain}")
        
        queries = [
            f'ip:"{ip}" http.headers:*',  # Headers for the specific IP
            f'hostname:"{domain}" http.headers:*'  # Headers for the hostname
        ]
        
        expected_security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy',
            'feature-policy'
        ]
        
        headers_found = set()
        
        for query in queries:
            try:
                search_results = api.search(query, limit=result_limit)
                
                if search_results['total'] == 0:
                    print(f"No HTTP header information found for query: {query}")
                    continue
                
                print(f"Found {search_results['total']} results with HTTP headers. Processing...")
                
                for result_item in search_results['matches']:
                    header_data = {
                        "ip": result_item.get('ip_str'),
                        "port": result_item.get('port'),
                        "protocol": "https" if result_item.get('port') == 443 else "http"
                    }
                    
                    if 'http' in result_item and 'headers' in result_item['http']:
                        security_headers = {}
                        all_headers = {}
                        
                        for header in result_item['http']['headers']:
                            name = header['name'].lower()
                            value = header['value']
                            all_headers[name] = value
                            
                            if name in expected_security_headers:
                                security_headers[name] = value
                                headers_found.add(name)
                        
                        header_data["security_headers"] = security_headers
                        header_data["all_headers"] = all_headers
                        
                        # Record server info if available
                        if 'server' in all_headers:
                            header_data["server"] = all_headers['server']
                        
                        result["security_headers"]["headers"].append(header_data)
            
            except shodan.APIError as e:
                print(f"Error executing query '{query}': {e}")
        
        # Analyze which security headers are missing
        missing_headers = [h for h in expected_security_headers if h not in headers_found]
        
        result["security_headers"]["analysis"] = {
            "headers_found": list(headers_found),
            "headers_missing": missing_headers,
            "score": (len(headers_found) / len(expected_security_headers)) * 100
        }
        
        print_section("Security Headers Analyzed")
        print(f"Found {len(headers_found)} of {len(expected_security_headers)} recommended security headers")
        print(f"Security header score: {result['security_headers']['analysis']['score']:.1f}%")
        return result
    
    except Exception as e:
        print(f"Error analyzing security headers: {e}")
        return result


def collect_vulnerabilities(api, ip, result_limit=5):
    """Check if the host has any known vulnerabilities"""
    result = {"vulnerabilities": []}
    
    try:
        print_section("Checking for vulnerabilities")
        print("NOTE: Direct vulnerability data through the Shodan API requires a Small Business or higher tier subscription.")
        print("      Using alternative methods to identify potential security issues...")
        
        # Instead of direct vuln check, we'll use other signals to identify potential issues
        host = api.host(ip, history=False)
        
        # Check for known risky services and common security issues
        risky_ports = {
            21: "FTP - Potential for anonymous access or outdated servers",
            22: "SSH - Check for older protocol versions (v1) or outdated implementations",
            23: "Telnet - Unencrypted communications, potential backdoor",
            25: "SMTP - Check for open relay or outdated mail servers",
            53: "DNS - Check for zone transfers or outdated DNS software",
            80: "HTTP - Unencrypted web traffic, check for outdated web servers",
            139: "NetBIOS - Windows file sharing, potential information disclosure",
            445: "SMB - Windows file sharing, check for EternalBlue and related issues",
            1433: "MSSQL - Database exposure, check for default credentials",
            1521: "Oracle DB - Database exposure, check for default credentials",
            3306: "MySQL - Database exposure, check for default credentials",
            3389: "RDP - Remote Desktop, brute force target",
            5432: "PostgreSQL - Database exposure, check for default credentials",
            6379: "Redis - Check for unauthenticated access",
            8080: "Alternative HTTP - Often used for admin interfaces",
            8443: "Alternative HTTPS - Often used for admin interfaces",
            27017: "MongoDB - Check for unauthenticated access"
        }
        
        if 'ports' in host:
            for port in host['ports']:
                if port in risky_ports:
                    finding = {
                        "type": "risky_service",
                        "port": port,
                        "service": risky_ports[port]
                    }
                    result["vulnerabilities"].append(finding)
        
        # Check for EOL/outdated software in service banners
        if 'data' in host:
            outdated_patterns = [
                {"pattern": "apache/1.", "name": "Apache 1.x (EOL)"},
                {"pattern": "apache/2.0", "name": "Apache 2.0.x (EOL)"},
                {"pattern": "apache/2.2", "name": "Apache 2.2.x (EOL)"},
                {"pattern": "nginx/0.", "name": "Nginx 0.x (EOL)"},
                {"pattern": "nginx/1.0", "name": "Nginx 1.0.x (EOL)"},
                {"pattern": "nginx/1.1", "name": "Nginx 1.1.x (EOL)"},
                {"pattern": "microsoft-iis/5.", "name": "IIS 5.x (EOL)"},
                {"pattern": "microsoft-iis/6.", "name": "IIS 6.x (EOL)"},
                {"pattern": "microsoft-iis/7.0", "name": "IIS 7.0 (EOL)"},
                {"pattern": "php/5.2", "name": "PHP 5.2.x (EOL)"},
                {"pattern": "php/5.3", "name": "PHP 5.3.x (EOL)"},
                {"pattern": "php/5.4", "name": "PHP 5.4.x (EOL)"},
                {"pattern": "php/5.5", "name": "PHP 5.5.x (EOL)"},
                {"pattern": "php/5.6", "name": "PHP 5.6.x (EOL)"},
                {"pattern": "openssh-4.", "name": "OpenSSH 4.x (EOL)"},
                {"pattern": "openssh-5.", "name": "OpenSSH 5.x (EOL)"},
                {"pattern": "openssh-6.0", "name": "OpenSSH 6.0.x (EOL)"}
            ]
            
            for service in host['data']:
                # Check product and version if available
                if 'product' in service and 'version' in service:
                    product_version = f"{service['product']}/{service['version']}".lower()
                    for pattern in outdated_patterns:
                        if pattern["pattern"].lower() in product_version:
                            finding = {
                                "type": "outdated_software",
                                "port": service.get('port'),
                                "protocol": service.get('transport', 'unknown'),
                                "product": service.get('product'),
                                "version": service.get('version'),
                                "issue": pattern["name"],
                                "recommendation": "Update to a supported version"
                            }
                            result["vulnerabilities"].append(finding)
                
                # Check SSL/TLS for weak protocols
                if 'ssl' in service:
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1']
                    if 'versions' in service['ssl']:
                        for protocol in weak_protocols:
                            if protocol in service['ssl']['versions']:
                                finding = {
                                    "type": "weak_encryption",
                                    "port": service.get('port'),
                                    "protocol": protocol,
                                    "issue": f"Weak protocol: {protocol}",
                                    "recommendation": "Disable old SSL/TLS versions and enable only TLSv1.2+ with strong ciphers"
                                }
                                result["vulnerabilities"].append(finding)
                    
                    # Check for weak ciphers
                    if 'cipher' in service['ssl']:
                        if service['ssl']['cipher'].get('bits', 0) < 128:
                            finding = {
                                "type": "weak_encryption",
                                "port": service.get('port'),
                                "cipher": service['ssl']['cipher'].get('name'),
                                "bits": service['ssl']['cipher'].get('bits'),
                                "issue": "Weak cipher strength (< 128 bits)",
                                "recommendation": "Configure server to use strong ciphers only"
                            }
                            result["vulnerabilities"].append(finding)
                
                # Check for HTTP security issues
                if 'http' in service:
                    # Check for missing security headers
                    if 'headers' in service['http']:
                        headers = {h['name'].lower(): h['value'] for h in service['http']['headers']}
                        security_headers = [
                            'strict-transport-security',
                            'content-security-policy',
                            'x-frame-options',
                            'x-content-type-options'
                        ]
                        
                        missing_headers = []
                        for header in security_headers:
                            if header not in headers:
                                missing_headers.append(header)
                        
                        if missing_headers:
                            finding = {
                                "type": "missing_security_headers",
                                "port": service.get('port'),
                                "missing_headers": missing_headers,
                                "issue": "Missing important security headers",
                                "recommendation": "Implement security headers to improve web security posture"
                            }
                            result["vulnerabilities"].append(finding)
        
        # Alternative to direct vulnerability data - show potential CVE matches
        print("Since vulnerability data isn't directly available, consider checking these resources:")
        print("1. Use the CPE strings from service info to check the NVD database:")
        print("   https://nvd.nist.gov/vuln/search")
        print("2. Check product versions against known CVEs manually")
        print("3. Consider using Shodan Monitor or a vulnerability scanner for more comprehensive results")
        
        # Give a summary of potential issues found
        if result["vulnerabilities"]:
            print(f"Found {len(result['vulnerabilities'])} potential security issues using alternative methods")
            
            # Count issues by type
            issue_types = {}
            for issue in result["vulnerabilities"]:
                issue_type = issue.get("type", "other")
                if issue_type in issue_types:
                    issue_types[issue_type] += 1
                else:
                    issue_types[issue_type] = 1
            
            print("Issues by type:")
            for issue_type, count in issue_types.items():
                print(f"- {issue_type}: {count}")
        else:
            print("No immediate security issues identified with the alternative methods")
            
        return result
    
    except shodan.APIError as e:
        if "vulns" in str(e).lower():
            print("Vulnerability checking is only available to paid Shodan subscriptions.")
        else:
            print(f"Error checking for security issues: {e}")
        return result


def collect_subdomains(api, domain, result_limit=5):
    """Collect subdomains from SSL certificates and DNS information"""
    result = {"subdomains": {"from_ssl": [], "from_dns": [], "consolidated": []}}
    
    if is_ip_address(domain):
        print_section("Subdomain Collection Skipped")
        print(f"Target {domain} is an IP address, skipping subdomain collection")
        return result
    
    try:
        print_section(f"Collecting subdomains for {domain}")
        
        # Extract base domain (e.g., example.com from www.example.com)
        base_domain = domain
        if base_domain.count('.') > 1:
            base_parts = base_domain.split('.')
            if len(base_parts) > 2:
                base_domain = '.'.join(base_parts[-2:])
        
        # Search for SSL certificates with wildcards and subject alternative names
        query = f'ssl:"{base_domain}"'
        print(f"Searching for SSL certificates with: {query}")
        
        try:
            search_results = api.search(query, limit=10)
            
            if search_results['total'] > 0:
                print(f"Found {search_results['total']} SSL certificates. Extracting subdomains...")
                
                for result_item in search_results['matches']:
                    if 'ssl' in result_item and 'cert' in result_item['ssl'] and 'extensions' in result_item['ssl']['cert']:
                        cert = result_item['ssl']['cert']
                        
                        # Get subject alternative names
                        if 'extensions' in cert and 'subjectAltName' in cert['extensions']:
                            alt_names = cert['extensions']['subjectAltName'].split(', ')
                            dns_names = [name.replace('DNS:', '') for name in alt_names if name.startswith('DNS:')]
                            
                            # Filter only subdomains of our base domain
                            filtered_dns_names = [name for name in dns_names if base_domain in name]
                            result["subdomains"]["from_ssl"].extend(filtered_dns_names)
        
        except shodan.APIError as e:
            print(f"Error searching SSL certificates: {e}")
        
        # Try to find more subdomains from DNS records and hostnames
        dns_query = f'hostname:".{base_domain}"'
        try:
            dns_results = api.search(dns_query, limit=20)
            
            if dns_results['total'] > 0:
                print(f"Found {dns_results['total']} DNS records. Extracting subdomains...")
                
                for result_item in dns_results['matches']:
                    if 'hostnames' in result_item:
                        for hostname in result_item['hostnames']:
                            if base_domain in hostname and hostname not in result["subdomains"]["from_dns"]:
                                result["subdomains"]["from_dns"].append(hostname)
                    
                    if 'domains' in result_item:
                        for domain_name in result_item['domains']:
                            if base_domain in domain_name and domain_name not in result["subdomains"]["from_dns"]:
                                result["subdomains"]["from_dns"].append(domain_name)
        
        except shodan.APIError as e:
            print(f"Error searching DNS records: {e}")
        
        # Deduplicate and consolidate subdomains
        all_subdomains = set(result["subdomains"]["from_ssl"] + result["subdomains"]["from_dns"])
        result["subdomains"]["consolidated"] = sorted(list(all_subdomains))
        result["subdomains"]["count"] = len(result["subdomains"]["consolidated"])
        
        print_section("Subdomain Collection Completed")
        print(f"Found {result['subdomains']['count']} unique subdomains")
        
        return result
    
    except Exception as e:
        print(f"Error collecting subdomains: {e}")
        return result


def collect_similar_hosts(api, ip, result_limit=5):
    """Find hosts with similar services and configurations"""
    result = {"similar_hosts": []}
    
    try:
        print_section("Finding similar hosts")
        # First get details about the target host
        host_info = api.host(ip)
        
        if 'ports' not in host_info or not host_info['ports']:
            print("No ports found for this host. Cannot find similar hosts.")
            return result
            
        # Get the top 3 most uncommon ports to make a more specific query
        ports = host_info['ports']
        if len(ports) > 3:
            ports = ports[:3]  # Just use the first 3 ports
            
        # Create a query for hosts with the same port signature
        port_query = " ".join([f"port:{port}" for port in ports])
        
        # Add organization if available
        org_filter = ""
        if 'org' in host_info and host_info['org']:
            org_filter = f" org:\"{host_info['org']}\""
        
        query = f"{port_query}{org_filter}"
        
        print(f"Searching for hosts with query: {query}")
        search_results = api.search(query, limit=result_limit)
        
        if search_results['total'] <= 1:
            print("No similar hosts found.")
            return result
            
        print(f"Found {search_results['total']} similar hosts. Processing first {result_limit}...")
        
        for result_item in search_results['matches']:
            # Skip the original host
            if result_item.get('ip_str') == ip:
                continue
                
            host_data = {
                "ip": result_item.get('ip_str'),
                "organization": result_item.get('org'),
                "ports": result_item.get('ports', []),
                "hostnames": result_item.get('hostnames', []),
                "location": {
                    "country": result_item.get('location', {}).get('country_name'),
                    "city": result_item.get('location', {}).get('city')
                }
            }
            
            # Get HTTP info if available
            if 'http' in result_item:
                http_info = {}
                if 'title' in result_item['http']:
                    http_info["title"] = result_item['http']['title']
                if 'server' in result_item['http']:
                    http_info["server"] = result_item['http']['server']
                
                if http_info:
                    host_data["http"] = http_info
            
            result["similar_hosts"].append(host_data)
        
        print_section("Similar Hosts Collected")
        print(f"Collected {len(result['similar_hosts'])} similar hosts")
        return result
    
    except shodan.APIError as e:
        print(f"Error finding similar hosts: {e}")
        return result


def collect_exposed_files(api, domain, ip):
    """Search for potentially exposed sensitive files"""
    result = {"exposed_files": {"findings": []}}
    
    try:
        print_section("Searching for exposed sensitive files")
        
        # List of common sensitive files and directories
        sensitive_patterns = [
            ".git",
            ".svn",
            ".env",
            "config",
            "backup",
            "db",
            "database",
            "admin",
            "wp-admin",
            "phpmyadmin",
            "phpinfo",
            ".htpasswd",
            "credentials",
            "password",
            "install",
            "setup"
        ]
        
        # Check for each pattern
        for pattern in sensitive_patterns:
            query = f'ip:"{ip}" http.html:"{pattern}"'
            try:
                results = api.search(query, limit=3)
                
                if results['total'] > 0:
                    print(f"Found potential {pattern} exposure ({results['total']} results)")
                    
                    for match in results['matches']:
                        finding = {
                            "pattern": pattern,
                            "ip": match.get('ip_str'),
                            "port": match.get('port'),
                            "hostnames": match.get('hostnames', [])
                        }
                        
                        if 'http' in match:
                            if 'title' in match['http']:
                                finding["page_title"] = match['http']['title']
                            if 'status' in match['http']:
                                finding["status_code"] = match['http']['status']
                            if 'location' in match['http']:
                                finding["redirect"] = match['http']['location']
                        
                        result["exposed_files"]["findings"].append(finding)
            
            except shodan.APIError as e:
                if "Daily search usage limit reached" in str(e):
                    print("Search limit reached, stopping sensitive file search.")
                    break
                else:
                    print(f"Error searching for {pattern}: {e}")
        
        # Check for directory listing
        dir_listing_query = f'ip:"{ip}" "Index of /"'
        try:
            dir_results = api.search(dir_listing_query, limit=3)
            
            if dir_results['total'] > 0:
                print(f"Found potential directory listing ({dir_results['total']} results)")
                
                for match in dir_results['matches']:
                    finding = {
                        "pattern": "directory_listing",
                        "ip": match.get('ip_str'),
                        "port": match.get('port'),
                        "hostnames": match.get('hostnames', [])
                    }
                    
                    if 'http' in match and 'title' in match['http']:
                        finding["page_title"] = match['http']['title']
                    
                    result["exposed_files"]["findings"].append(finding)
        
        except shodan.APIError as e:
            print(f"Error searching for directory listing: {e}")
        
        print_section("Exposed Files Search Completed")
        print(f"Found {len(result['exposed_files']['findings'])} potentially exposed files/directories")
        return result
    
    except Exception as e:
        print(f"Error searching for exposed files: {e}")
        return result


def collect_http_errors(api, domain, ip):
    """Collect information about HTTP error responses"""
    result = {"http_errors": []}
    
    try:
        print_section("Searching for HTTP error responses")
        
        # Search for different HTTP error codes
        error_codes = [400, 401, 403, 404, 500, 502, 503]
        
        for code in error_codes:
            query = f'ip:"{ip}" http.status:{code}'
            try:
                results = api.search(query, limit=3)
                
                if results['total'] > 0:
                    print(f"Found {results['total']} responses with status code {code}")
                    
                    for match in results['matches']:
                        error_data = {
                            "status_code": code,
                            "ip": match.get('ip_str'),
                            "port": match.get('port'),
                            "hostnames": match.get('hostnames', []),
                            "timestamp": match.get('timestamp')
                        }
                        
                        if 'http' in match:
                            if 'title' in match['http']:
                                error_data["page_title"] = match['http']['title']
                            if 'location' in match['http']:
                                error_data["redirect"] = match['http']['location']
                        
                        result["http_errors"].append(error_data)
            
            except shodan.APIError as e:
                if "Daily search usage limit reached" in str(e):
                    print("Search limit reached, stopping HTTP error search.")
                    break
                else:
                    print(f"Error searching for status code {code}: {e}")
        
        print_section("HTTP Error Collection Completed")
        print(f"Found {len(result['http_errors'])} HTTP error responses")
        return result
    
    except Exception as e:
        print(f"Error collecting HTTP errors: {e}")
        return result


def save_results(results, filename, pretty=False):
    """Save results to a JSON file"""
    try:
        print_banner(f"Saving Results")
        if pretty:
            json_data = json.dumps(results, indent=4, sort_keys=True, default=str)
        else:
            json_data = json.dumps(results, default=str)
            
        with open(filename, 'w') as f:
            f.write(json_data)
            
        print(f"Results saved to: {os.path.abspath(filename)}")
        print(f"File size: {os.path.getsize(filename) / 1024:.2f} KB")
    except Exception as e:
        print(f"Error saving results: {e}")


def perform_basic_ssl_analysis(domain):
    """Perform basic SSL analysis without Shodan API"""
    result = {"basic_ssl_analysis": {"findings": []}}
    
    if is_ip_address(domain):
        print_section("Basic SSL Analysis Skipped")
        print(f"Target {domain} is an IP address, skipping SSL analysis")
        return result
    
    try:
        print_section(f"Analyzing SSL configuration for {domain}")
        
        import ssl
        import socket
        from datetime import datetime
        
        # Test HTTPS connection
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Basic certificate information
                cert_info = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "version": cert.get('version'),
                    "serial_number": str(cert.get('serialNumber', '')),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter')
                }
                
                result["basic_ssl_analysis"]["certificate"] = cert_info
                
                # Check certificate expiration
                try:
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.utcnow()
                    days_left = (expires - now).days
                    
                    if days_left < 30:
                        severity = "High" if days_left < 7 else "Medium"
                        result["basic_ssl_analysis"]["findings"].append({
                            "type": "certificate_expiry",
                            "severity": severity,
                            "description": f"SSL certificate expires in {days_left} days",
                            "expiry_date": cert['notAfter'],
                            "days_remaining": days_left
                        })
                except Exception as e:
                    print(f"Error parsing certificate expiration: {e}")
                
                # Check for subject alternative names
                if 'subjectAltName' in cert:
                    alt_names = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                    result["basic_ssl_analysis"]["alternative_names"] = alt_names
                
                # Check SSL/TLS protocol version
                protocol_version = ssock.version()
                result["basic_ssl_analysis"]["protocol_version"] = protocol_version
                
                if protocol_version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                    result["basic_ssl_analysis"]["findings"].append({
                        "type": "weak_protocol",
                        "severity": "High",
                        "description": f"Weak SSL/TLS protocol version: {protocol_version}",
                        "protocol": protocol_version
                    })
                
                print(f"SSL analysis completed. Found {len(result['basic_ssl_analysis']['findings'])} issues")
                
    except ssl.SSLError as e:
        result["basic_ssl_analysis"]["error"] = f"SSL Error: {str(e)}"
        print(f"SSL Error: {e}")
    except socket.error as e:
        result["basic_ssl_analysis"]["error"] = f"Connection Error: {str(e)}"
        print(f"Connection Error: {e}")
    except Exception as e:
        result["basic_ssl_analysis"]["error"] = f"Unexpected Error: {str(e)}"
        print(f"Error during SSL analysis: {e}")
    
    return result


def perform_basic_header_analysis(domain):
    """Perform basic HTTP header analysis without Shodan API"""
    result = {"basic_header_analysis": {"findings": []}}
    
    if is_ip_address(domain):
        print_section("Basic Header Analysis")
        print(f"Analyzing headers for IP address: {domain}")
        base_urls = [f"http://{domain}", f"https://{domain}"]
    else:
        print_section(f"Analyzing HTTP headers for {domain}")
        base_urls = [f"https://{domain}", f"http://{domain}"]
    
    try:
        for base_url in base_urls:
            try:
                print(f"Testing {base_url}...")
                response = requests.get(base_url, timeout=10, verify=False, 
                                        allow_redirects=True,
                                        headers={'User-Agent': 'Mozilla/5.0 Security Scanner'})
                
                # Collect headers
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # Security headers to check
                security_headers = {
                    'strict-transport-security': "HTTP Strict Transport Security (HSTS)",
                    'content-security-policy': "Content Security Policy (CSP)",
                    'x-frame-options': "X-Frame-Options",
                    'x-content-type-options': "X-Content-Type-Options",
                    'x-xss-protection': "X-XSS-Protection",
                    'referrer-policy': "Referrer Policy",
                    'permissions-policy': "Permissions Policy"
                }
                
                # Check for missing security headers
                missing_headers = []
                present_headers = {}
                
                for header, name in security_headers.items():
                    if header in headers:
                        present_headers[header] = headers[header]
                    else:
                        missing_headers.append(name)
                
                if missing_headers:
                    severity = "High" if len(missing_headers) > 4 else "Medium"
                    result["basic_header_analysis"]["findings"].append({
                        "type": "missing_security_headers",
                        "severity": severity,
                        "url": base_url,
                        "description": f"Missing security headers: {', '.join(missing_headers)}",
                        "missing_headers": missing_headers,
                        "present_headers": present_headers
                    })
                
                # Check for information disclosure headers
                disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
                disclosed_info = {}
                
                for header in disclosure_headers:
                    if header in headers:
                        disclosed_info[header] = headers[header]
                
                if disclosed_info:
                    result["basic_header_analysis"]["findings"].append({
                        "type": "information_disclosure",
                        "severity": "Low",
                        "url": base_url,
                        "description": "Headers reveal server/framework information",
                        "disclosed_headers": disclosed_info
                    })
                
                # Check CORS configuration
                if 'access-control-allow-origin' in headers:
                    cors_origin = headers['access-control-allow-origin']
                    if cors_origin == '*':
                        result["basic_header_analysis"]["findings"].append({
                            "type": "cors_misconfiguration",
                            "severity": "Medium",
                            "url": base_url,
                            "description": "CORS allows all origins (*)",
                            "cors_origin": cors_origin
                        })
                
                # Store successful response info
                result["basic_header_analysis"]["successful_url"] = base_url
                result["basic_header_analysis"]["status_code"] = response.status_code
                result["basic_header_analysis"]["all_headers"] = dict(response.headers)
                
                break  # Success, no need to try other URLs
                
            except requests.exceptions.RequestException as e:
                print(f"Failed to connect to {base_url}: {e}")
                continue
        
        print(f"Header analysis completed. Found {len(result['basic_header_analysis']['findings'])} issues")
        
    except Exception as e:
        result["basic_header_analysis"]["error"] = f"Error during header analysis: {str(e)}"
        print(f"Error during header analysis: {e}")
    
    return result


def perform_active_scanning(domain):
    """Perform active scanning to identify web vulnerabilities"""
    print_section("Performing active web vulnerability scanning")
    print("This uses direct requests to the target to identify common web security issues")
    
    result = {"active_scan_vulnerabilities": []}
    
    if is_ip_address(domain):
        print("Active scanning is only available for domains, not IP addresses")
        return result
    
    try:
        # Ask for user confirmation before active scanning
        print(f"About to perform active scanning on {domain}")
        print("Note: Active scanning sends requests directly to the target server")
        
        # Perform the scan
        scan_results = perform_active_web_scan(domain)
        
        # Convert scan results to vulnerability format
        vulnerabilities = []
        
        if scan_results and not scan_results.get('error'):
            # Check for common security issues
            if scan_results.get('discovered_paths'):
                for path_info in scan_results['discovered_paths']:
                    if path_info['path'] in ['/admin', '/administrator', '/wp-admin', '/phpmyadmin']:
                        vulnerabilities.append({
                            "name": "Administrative Interface Exposed",
                            "severity": "Medium",
                            "description": f"Administrative interface found at {path_info['path']}",
                            "evidence": path_info
                        })
            
            # Check for missing HTTPS
            if not scan_results.get('https_available', False):
                vulnerabilities.append({
                    "name": "Missing HTTPS",
                    "severity": "Medium", 
                    "description": "Website does not support HTTPS encryption",
                    "evidence": {"https_available": False}
                })
            
            # Check for excessive open ports
            open_ports = scan_results.get('open_ports', [])
            if len(open_ports) > 5:
                vulnerabilities.append({
                    "name": "Multiple Open Ports",
                    "severity": "Low",
                    "description": f"Found {len(open_ports)} open ports which may increase attack surface",
                    "evidence": {"open_ports": open_ports}
                })
        
        if vulnerabilities:
            result["active_scan_vulnerabilities"] = vulnerabilities
            print(f"Found {len(vulnerabilities)} potential vulnerabilities through active scanning")
            
            # Categorize findings by severity
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Low")
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Print summary by severity
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"{severity}: {count}")
        else:
            print("No vulnerabilities found through active scanning")
        
        return result
    
    except Exception as e:
        print(f"Error during active scanning: {e}")
        return result


def check_web_vulnerabilities(api, domain, ip, result_limit=5):
    """Check for common web vulnerabilities based on available data without requiring premium access"""
    result = {"web_vulnerabilities": []}
    
    try:
        print_section("Checking for common web vulnerabilities")
        print("Using alternative detection methods that work with standard Shodan subscription")
        
        # First, let's collect HTTP services data to analyze locally
        # This reduces API calls and allows us to analyze data we already have
        http_services = []
        try:
            host_data = api.host(ip, minify=False)
            if 'data' in host_data:
                for service in host_data['data']:
                    if 'http' in service:
                        http_services.append(service)
            
            print(f"Found {len(http_services)} HTTP services to analyze for vulnerabilities")
            
            # Try to actively probe the host for additional vulnerability detection
            # This uses direct HTTP requests to analyze responses
            if not is_ip_address(domain):
                print("Attempting to analyze live HTTP responses for detailed vulnerability detection...")
                try:
                    protocols = ['https', 'http']
                    additional_paths = ['/', '/login', '/admin', '/wp-admin', '/phpinfo.php', '/test.php']
                    for protocol in protocols:
                        for path in additional_paths:
                            try:
                                target_url = f"{protocol}://{domain}{path}"
                                response = requests.get(target_url, timeout=5, 
                                                       verify=False,  # Skip SSL verification for testing
                                                       headers={'User-Agent': 'Mozilla/5.0 Vulnerability Scanner'})
                                
                                # Get response headers (lowercase keys for consistency)
                                headers = {k.lower(): v for k, v in response.headers.items()}
                                
                                # Analyze the response for vulnerabilities
                                findings = analyze_http_response(target_url, headers, response.text, response.status_code)
                                
                                # Add findings to our results
                                for finding in findings:
                                    finding["url"] = target_url
                                    finding["status_code"] = response.status_code
                                    result["web_vulnerabilities"].append(finding)
                                
                                # Check server header for known CVEs
                                if 'server' in headers:
                                    server_name, version = extract_version_from_server_header(headers['server'])
                                    if server_name and version:
                                        cve_info = check_for_cve(server_name, version)
                                        if cve_info:
                                            finding = {
                                                "name": f"Known Vulnerability in {server_name}/{version}",
                                                "severity": "High",
                                                "description": f"Server version matches known vulnerability: {cve_info['cve_description']}",
                                                "remediation": "Update to the latest patched version",
                                                "evidence": {
                                                    "server": headers['server'],
                                                    "url": target_url,
                                                    "cve_info": cve_info
                                                }
                                            }
                                            result["web_vulnerabilities"].append(finding)
                            
                            except requests.exceptions.RequestException:
                                # Silently continue if a request fails
                                pass
                except Exception as e:
                    print(f"Error during live HTTP analysis: {e}")
        except shodan.APIError as e:
            print(f"Error retrieving host data: {e}")
        
        # Local analysis of collected data
        if http_services:
            # Check for version-specific vulnerabilities in web servers
            web_server_vulns = {
                "apache/1.": {"name": "Apache 1.x", "vuln": "Multiple critical vulnerabilities, EOL", "severity": "Critical"},
                "apache/2.0": {"name": "Apache 2.0.x", "vuln": "Multiple vulnerabilities, EOL", "severity": "High"},
                "apache/2.2": {"name": "Apache 2.2.x", "vuln": "Multiple vulnerabilities including CVE-2017-9798", "severity": "High"},
                "nginx/0.": {"name": "Nginx 0.x", "vuln": "Multiple vulnerabilities, EOL", "severity": "High"},
                "nginx/1.0": {"name": "Nginx 1.0.x", "vuln": "Multiple vulnerabilities, EOL", "severity": "High"},
                "nginx/1.1": {"name": "Nginx 1.1.x", "vuln": "Multiple vulnerabilities, EOL", "severity": "High"},
                "microsoft-iis/5.": {"name": "IIS 5.x", "vuln": "Multiple critical vulnerabilities including WebDAV RCE", "severity": "Critical"},
                "microsoft-iis/6.": {"name": "IIS 6.x", "vuln": "Multiple vulnerabilities including CVE-2017-7269", "severity": "Critical"},
                "microsoft-iis/7.0": {"name": "IIS 7.0", "vuln": "Multiple vulnerabilities", "severity": "High"},
                "jetty": {"name": "Jetty", "vuln": "Check against known Jetty vulnerabilities", "severity": "Medium"},
                "tomcat": {"name": "Tomcat", "vuln": "Check against known Tomcat vulnerabilities", "severity": "Medium"},
                "weblogic": {"name": "WebLogic", "vuln": "Check against known WebLogic vulnerabilities", "severity": "High"}
            }
            
            for service in http_services:
                # Get server header if it exists
                server_header = None
                if 'http' in service and 'headers' in service['http']:
                    headers = {h['name'].lower(): h['value'] for h in service['http']['headers']}
                    if 'server' in headers:
                        server_header = headers['server'].lower()
                
                if server_header:
                    for signature, vuln_info in web_server_vulns.items():
                        if signature.lower() in server_header:
                            finding = {
                                "name": f"Vulnerable {vuln_info['name']}",
                                "severity": vuln_info['severity'],
                                "description": f"Detected {server_header} - {vuln_info['vuln']}",
                                "remediation": "Update to the latest stable version",
                                "evidence": {
                                    "server_header": server_header,
                                    "port": service.get('port'),
                                    "ip": ip
                                }
                            }
                            result["web_vulnerabilities"].append(finding)
                
                # Check for missing security headers
                if 'http' in service and 'headers' in service['http']:
                    headers = {h['name'].lower(): h['value'] for h in service['http']['headers']}
                    critical_headers = {
                        'strict-transport-security': "HTTP Strict Transport Security",
                        'content-security-policy': "Content Security Policy",
                        'x-frame-options': "X-Frame-Options",
                        'x-content-type-options': "X-Content-Type-Options"
                    }
                    
                    missing = []
                    for header, name in critical_headers.items():
                        if header not in headers:
                            missing.append(name)
                    
                    if missing and len(missing) >= 2:  # Only report if multiple critical headers are missing
                        severity = "High" if "HTTP Strict Transport Security" in missing else "Medium"
                        finding = {
                            "name": "Missing Security Headers",
                            "severity": severity,
                            "description": f"Missing critical security headers: {', '.join(missing)}",
                            "remediation": "Implement the missing security headers to protect against XSS, clickjacking, and other attacks",
                            "evidence": {
                                "port": service.get('port'),
                                "missing_headers": missing,
                                "existing_headers": list(headers.keys())
                            }
                        }
                        result["web_vulnerabilities"].append(finding)
                
                # Check for CORS misconfiguration
                if 'http' in service and 'headers' in service['http']:
                    headers = {h['name'].lower(): h['value'] for h in service['http']['headers']}
                    if 'access-control-allow-origin' in headers and headers['access-control-allow-origin'] == '*':
                        if any(sensitive in headers.get('access-control-allow-headers', '').lower() for sensitive in ['authorization', 'cookie']):
                            finding = {
                                "name": "CORS Misconfiguration",
                                "severity": "High",
                                "description": "CORS is configured to allow all origins (*) while allowing credentials",
                                "remediation": "Restrict CORS to specific origins instead of using wildcard (*)",
                                "evidence": {
                                    "port": service.get('port'),
                                    "cors_headers": {k: v for k, v in headers.items() if 'access-control' in k}
                                }
                            }
                            result["web_vulnerabilities"].append(finding)
                
                # Check for information disclosure in HTTP responses
                if 'http' in service:
                    info_leaks = []
                    
                    # Check headers for information leakage
                    if 'headers' in service['http']:
                        headers = {h['name'].lower(): h['value'] for h in service['http']['headers']}
                        
                        # Check for server version disclosure
                        if 'server' in headers and any(char.isdigit() for char in headers['server']):
                            info_leaks.append(f"Server header reveals version: {headers['server']}")
                        
                        # Check for framework disclosure
                        if 'x-powered-by' in headers:
                            info_leaks.append(f"X-Powered-By reveals framework: {headers['x-powered-by']}")
                        
                        # Check for ASP.NET version disclosure
                        if 'x-aspnet-version' in headers:
                            info_leaks.append(f"ASP.NET version disclosed: {headers['x-aspnet-version']}")
                    
                    # Check HTML for developer comments
                    if 'html' in service['http'] and len(service['http']['html']) > 0:
                        html = service['http']['html']
                        if "<!--" in html and "-->" in html and any(dev_term in html.lower() for dev_term in ['todo', 'fixme', 'note:', 'debug']):
                            info_leaks.append("Developer comments found in HTML source")
                    
                    if info_leaks:
                        finding = {
                            "name": "Information Disclosure",
                            "severity": "Medium",
                            "description": "The application reveals sensitive technical information",
                            "remediation": "Configure servers to hide version information and remove developer comments",
                            "evidence": {
                                "port": service.get('port'),
                                "leaks": info_leaks
                            }
                        }
                        result["web_vulnerabilities"].append(finding)
        
        # Common patterns to look for using Shodan search
        vulnerability_signatures = [
            {
                "name": "Directory Listing Enabled",
                "query": f'ip:"{ip}" http.title:"Index of"',
                "severity": "Medium",
                "description": "Directory listing is enabled, which can reveal sensitive files and folder structure",
                "remediation": "Disable directory listing in web server configuration"
            },
            {
                "name": "Exposed .git Repository",
                "query": f'ip:"{ip}" http.html:".git"',
                "severity": "High",
                "description": "Git repository metadata may be exposed, leaking source code and sensitive information",
                "remediation": "Block access to .git directories in web server configuration"
            },
            {
                "name": "Exposed Environment File",
                "query": f'ip:"{ip}" http.html:".env"',
                "severity": "Critical",
                "description": "Environment configuration file may be exposed, potentially containing credentials",
                "remediation": "Block access to .env files and never store them in publicly accessible directories"
            }
        ]
        
        # Check each vulnerability pattern
        for vuln in vulnerability_signatures:
            try:
                print(f"Checking for: {vuln['name']}")
                results = api.search(vuln['query'], limit=3)
                
                if results['total'] > 0:
                    print(f"Found potential {vuln['name']} vulnerability ({results['total']} matches)")
                    
                    finding = {
                        "name": vuln['name'],
                        "severity": vuln['severity'],
                        "matches": results['total'],
                        "description": vuln['description'],
                        "remediation": vuln['remediation'],
                        "evidence": []
                    }
                    
                    # Add evidence from the first few matches
                    for match in results['matches'][:3]:  # Limit to first 3 matches
                        evidence = {
                            "ip": match.get('ip_str'),
                            "port": match.get('port')
                        }
                        
                        if 'http' in match:
                            if 'title' in match['http']:
                                evidence["page_title"] = match['http']['title']
                            if 'status' in match['http']:
                                evidence["status_code"] = match['http']['status']
                                
                            # Get a relevant snippet if possible, without including full HTML
                            if 'html' in match['http'] and len(match['http']['html']) > 0:
                                # Just store a hash or limited snippet to avoid huge data
                                evidence["html_hash"] = hash(match['http']['html'])
                        
                        finding["evidence"].append(evidence)
                    
                    result["web_vulnerabilities"].append(finding)
            
            except shodan.APIError as e:
                if "Daily search usage limit reached" in str(e):
                    print("Search limit reached, stopping web vulnerability checks.")
                    break
                else:
                    print(f"Error checking for {vuln['name']}: {e}")
        
        # Check for common CMS vulnerabilities
        try:
            # First identify if any common CMS is running - use simpler query to avoid "OR" issues
            cms_query = f'ip:"{ip}" http.component:*'
            cms_results = api.search(cms_query, limit=result_limit)
            
            if cms_results['total'] > 0:
                for match in cms_results['matches']:
                    if 'http' in match and 'components' in match['http']:
                        cms_name = None
                        cms_version = None
                        
                        for comp_name, comp_details in match['http']['components'].items():
                            lower_name = comp_name.lower()
                            if any(cms in lower_name for cms in ['wordpress', 'drupal', 'joomla']):
                                cms_name = comp_name
                                cms_version = comp_details.get('version')
                                break
                        
                        if cms_name:
                            finding = {
                                "name": f"{cms_name} Detected",
                                "severity": "Info",
                                "description": f"Found {cms_name} {cms_version or 'unknown version'}"
                            }
                            
                            # Add version-specific warnings if version is old or known vulnerable
                            if cms_version:
                                # This is a simplified check - in a real tool, you'd check against a CVE database
                                if cms_name.lower() == 'wordpress':
                                    version_parts = cms_version.split('.')
                                    if len(version_parts) > 1:
                                        major = int(version_parts[0])
                                        if major < 5:
                                            finding["severity"] = "Medium"
                                            finding["description"] += " (older version that may contain vulnerabilities)"
                                            finding["remediation"] = "Update WordPress to the latest version"
                                
                                elif cms_name.lower() == 'drupal':
                                    version_parts = cms_version.split('.')
                                    if len(version_parts) > 0:
                                        major = int(version_parts[0])
                                        if major < 8:
                                            finding["severity"] = "High"
                                            finding["description"] += " (older version that may contain vulnerabilities)"
                                            finding["remediation"] = "Update Drupal to the latest version"
                                
                                elif cms_name.lower() == 'joomla':
                                    version_parts = cms_version.split('.')
                                    if len(version_parts) > 0:
                                        major = int(version_parts[0])
                                        if major < 3:
                                            finding["severity"] = "Medium"
                                            finding["description"] += " (older version that may contain vulnerabilities)"
                                            finding["remediation"] = "Update Joomla to the latest version"
                            
                            result["web_vulnerabilities"].append(finding)
        
        except shodan.APIError as e:
            print(f"Error checking for CMS vulnerabilities: {e}")
        
        print_section("Web Vulnerability Check Completed")
        print(f"Found {len(result['web_vulnerabilities'])} potential web vulnerabilities")
        
        # Group findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in result["web_vulnerabilities"]:
            severity = vuln.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Print summary by severity
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"{severity}: {count}")
        
        return result
    
    except Exception as e:
        print(f"Error checking for web vulnerabilities: {e}")
        return result


def perform_comprehensive_noshodan_scan(target, max_workers=10):
    """Comprehensive scanner that replicates all Shodan functionality without API"""
    results = {
        "host_info": {},
        "services": [],
        "subdomains": {"consolidated": []},
        "related_hosts": [],
        "ssl_certificates": [],
        "web_technologies": [],
        "security_headers": {"analysis": {}, "headers": []},
        "vulnerabilities": [],
        "web_vulnerabilities": [],
        "exposed_files": {"findings": []},
        "active_scan_vulnerabilities": []
    }
    
    print_banner(f"Comprehensive No-Shodan Scan of {target}")
    
    # Resolve target
    ip = resolve_target_comprehensive(target, results)
    if not ip:
        return results
    
    # Gather basic host information
    gather_basic_host_info(target, ip, results)
    
    # Port scanning and service identification
    open_ports = scan_ports_comprehensive(ip, max_workers)
    if open_ports:
        results["host_info"]["ports"] = open_ports
        identify_services_comprehensive(target, ip, open_ports, results, max_workers)
    
    # Subdomain discovery
    discover_subdomains_comprehensive(target, results, max_workers)
    
    # Web technology analysis
    analyze_web_technologies_comprehensive(target, results)
    
    # Security analysis
    analyze_security_headers_comprehensive(target, results)
    check_vulnerabilities_comprehensive(target, ip, results)
    
    # Active web scanning
    perform_active_web_scan_comprehensive(target, results)
    
    return results


def resolve_target_comprehensive(target, results):
    """Resolve domain to IP and gather basic DNS info"""
    try:
        print_section("Resolving target and gathering DNS information")
        
        if is_ip_address(target):
            ip = target
            # Try reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                results["host_info"]["hostnames"] = [hostname]
                print(f"Reverse DNS: {ip} -> {hostname}")
            except:
                print(f"No reverse DNS found for {ip}")
        else:
            ip = socket.gethostbyname(target)
            results["host_info"]["hostnames"] = [target]
            print(f"Domain {target} resolves to IP: {ip}")
        
        results["host_info"]["ip"] = ip
        
        # Try to get additional DNS records
        try:
            # Get all A records
            result = subprocess.run(['nslookup', target], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse nslookup output for additional info
                output = result.stdout
                if "Non-authoritative answer" in output:
                    results["host_info"]["dns_info"] = "Non-authoritative DNS response"
        except:
            pass
        
        return ip
    except Exception as e:
        print(f"Error resolving target: {e}")
        return None


def gather_basic_host_info(target, ip, results):
    """Gather basic host information similar to Shodan"""
    print_section("Gathering basic host information")
    
    try:
        # Try to get geolocation info (using a free service)
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                if geo_data.get("status") == "success":
                    results["host_info"]["location"] = {
                        "country": geo_data.get("country"),
                        "country_code": geo_data.get("countryCode"),
                        "region": geo_data.get("regionName"),
                        "city": geo_data.get("city"),
                        "latitude": geo_data.get("lat"),
                        "longitude": geo_data.get("lon"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org"),
                        "as": geo_data.get("as")
                    }
                    print(f"Location: {geo_data.get('city')}, {geo_data.get('country')}")
                    print(f"ISP: {geo_data.get('isp')}")
        except Exception as e:
            print(f"Could not retrieve geolocation: {e}")
        
        # Try to get AS information
        try:
            # Simple AS lookup using whois (if available)
            whois_result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=15)
            if whois_result.returncode == 0:
                whois_output = whois_result.stdout.lower()
                # Extract ASN if present
                asn_match = re.search(r'as(\d+)', whois_output)
                if asn_match:
                    results["host_info"]["asn"] = f"AS{asn_match.group(1)}"
        except:
            pass
        
        # Set timestamp
        results["host_info"]["last_update"] = datetime.now().isoformat()
        
    except Exception as e:
        print(f"Error gathering basic host info: {e}")


def scan_ports_comprehensive(ip, max_workers=20):
    """Comprehensive port scanning similar to Shodan"""
    print_section("Scanning ports comprehensively")
    
    # Extended port list covering most common services
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
        9200, 9300, 27017, 5984, 5985, 5986, 2049, 111, 113, 119, 137, 138,
        389, 636, 902, 1234, 1337, 1521, 1723, 2082, 2083, 2086, 2087, 2095,
        2096, 3128, 4443, 5000, 5001, 5060, 5432, 5800, 5801, 5802, 5803,
        6000, 6001, 6667, 7000, 7001, 7002, 8000, 8008, 8009, 8081, 8082,
        8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8180, 8181, 8182,
        8443, 8800, 8880, 8888, 9000, 9001, 9002, 9080, 9090, 9100, 9443,
        9999, 10000, 11211, 15672, 50070
    ]
    
    print(f"Scanning {len(common_ports)} ports on {ip}...")
    open_ports = []
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in common_ports}
        for future in as_completed(future_to_port):
            port = future.result()
            if port:
                open_ports.append(port)
    
    open_ports.sort()
    print(f"Found {len(open_ports)} open ports: {open_ports}")
    return open_ports


def identify_services_comprehensive(target, ip, open_ports, results, max_workers=10):
    """Comprehensive service identification similar to Shodan"""
    print_section("Identifying services on open ports")
    
    def identify_service(port):
        service_info = {
            "port": port,
            "transport": "tcp",
            "service": get_service_name_comprehensive(port),
            "banner": None,
            "product": None,
            "version": None,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Special handling for different service types
            if port == 80:
                service_info.update(analyze_http_service(target, ip, port, False))
            elif port == 443:
                service_info.update(analyze_https_service_comprehensive(target, ip, port, results))
            elif port in [21, 22, 25, 110, 143, 993, 995]:
                service_info.update(grab_banner_service(ip, port))
            elif port == 53:
                service_info.update(analyze_dns_service(ip, port))
            elif port in [139, 445]:
                service_info.update(analyze_smb_service(ip, port))
            elif port in [1433, 3306, 5432, 27017]:
                service_info.update(analyze_database_service(ip, port))
            else:
                service_info.update(grab_generic_banner(ip, port))
                
        except Exception as e:
            service_info["error"] = str(e)
        
        return service_info
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        service_futures = {executor.submit(identify_service, port): port for port in open_ports}
        for future in as_completed(service_futures):
            service = future.result()
            if service:
                results["services"].append(service)
    
    print(f"Identified {len(results['services'])} services")


def get_service_name_comprehensive(port):
    """Get comprehensive service name for port"""
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
        445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "mssql",
        1521: "oracle", 1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb", 5984: "couchdb",
        2049: "nfs", 111: "rpcbind", 389: "ldap", 636: "ldaps", 5060: "sip",
        11211: "memcached", 50070: "hadoop"
    }
    return services.get(port, "unknown")


# Helper functions for comprehensive scanning
def analyze_http_service(target, ip, port, is_https=False):
    """Analyze HTTP service comprehensively"""
    service_info = {"http": {}}
    
    try:
        protocol = "https" if is_https else "http"
        url = f"{protocol}://{target}:{port}" if port != (443 if is_https else 80) else f"{protocol}://{target}"
        
        response = requests.get(url, timeout=10, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0 Comprehensive Scanner'},
                                allow_redirects=False)
        
        # Basic HTTP info
        service_info["http"]["status"] = response.status_code
        service_info["http"]["title"] = extract_title_from_html(response.text)
        
        # Headers analysis
        headers_list = []
        for name, value in response.headers.items():
            headers_list.append({"name": name, "value": value})
        service_info["http"]["headers"] = headers_list
        
        # Server information
        if 'Server' in response.headers:
            service_info["http"]["server"] = response.headers['Server']
            service_info["product"] = response.headers['Server'].split('/')[0] if '/' in response.headers['Server'] else response.headers['Server']
        
        # Technology detection
        components = detect_web_technologies(response.text, response.headers)
        if components:
            service_info["http"]["components"] = components
        
        # Store HTML hash for similarity comparison
        if response.text:
            service_info["http"]["html_hash"] = hash(response.text)
        
        # Check for redirects
        if 'Location' in response.headers:
            service_info["http"]["location"] = response.headers['Location']
        
    except Exception as e:
        service_info["error"] = str(e)
    
    return service_info


def analyze_https_service_comprehensive(target, ip, port, results):
    """Comprehensive HTTPS service analysis"""
    import ssl
    service_info = {"ssl": {}}
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    cert_info = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial": str(cert.get('serialNumber', '')),
                        "issued": cert.get('notBefore'),
                        "expires": cert.get('notAfter'),
                        "extensions": {}
                    }
                    
                    if 'subjectAltName' in cert:
                        alt_names = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                        cert_info['extensions']['subjectAltName'] = ', '.join(alt_names)
                    
                    service_info["ssl"]["cert"] = cert_info
                    
                    # Store certificate for SSL analysis
                    results["ssl_certificates"].append({
                        "ip": ip,
                        "port": port,
                        "hostnames": [target],
                        "timestamp": datetime.now().isoformat(),
                        "details": cert_info
                    })
                
                # SSL/TLS protocol and cipher info
                service_info["ssl"]["versions"] = [ssock.version()]
                if ssock.cipher():
                    service_info["ssl"]["cipher"] = {
                        "name": ssock.cipher()[0],
                        "version": ssock.cipher()[1],
                        "bits": ssock.cipher()[2]
                    }
        
        # Also analyze HTTP over HTTPS
        http_info = analyze_http_service(target, ip, port, True)
        service_info.update(http_info)
        
    except Exception as e:
        service_info["error"] = str(e)
    
    return service_info


def grab_banner_service(ip, port):
    """Grab banner from text-based services"""
    service_info = {}
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        
        # Send appropriate request based on port
        if port == 21:  # FTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        elif port == 22:  # SSH
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        elif port == 25:  # SMTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        elif port in [110, 995]:  # POP3
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        elif port in [143, 993]:  # IMAP
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        else:
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        service_info["banner"] = banner.strip()
        
        # Extract product and version from banner
        product, version = extract_product_version_from_banner(banner)
        if product:
            service_info["product"] = product
        if version:
            service_info["version"] = version
        
        sock.close()
        
    except Exception as e:
        service_info["error"] = str(e)
    
    return service_info


def analyze_dns_service(ip, port):
    """Analyze DNS service"""
    service_info = {"service": "dns"}
    
    try:
        # Try to query the DNS server
        result = subprocess.run(['nslookup', 'google.com', ip], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            service_info["dns_response"] = "Active DNS server"
        else:
            service_info["dns_response"] = "DNS query failed"
    except:
        service_info["dns_response"] = "Could not test DNS"
    
    return service_info


def analyze_smb_service(ip, port):
    """Analyze SMB/NetBIOS service"""
    service_info = {"service": "smb" if port == 445 else "netbios"}
    
    try:
        # Try to get SMB information
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        
        # Send SMB negotiate request (simplified)
        if port == 445:
            service_info["smb_info"] = "SMB service detected"
        else:
            service_info["netbios_info"] = "NetBIOS service detected"
        
        sock.close()
        
    except Exception as e:
        service_info["error"] = str(e)
    
    return service_info


def analyze_database_service(ip, port):
    """Analyze database services"""
    service_info = {}
    
    db_types = {
        1433: "mssql",
        3306: "mysql", 
        5432: "postgresql",
        27017: "mongodb"
    }
    
    service_info["service"] = db_types.get(port, "database")
    
    try:
        # Try to connect and get version info
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        
        if port == 3306:  # MySQL
            # MySQL sends greeting packet immediately
            greeting = sock.recv(1024)
            if greeting:
                service_info["mysql_greeting"] = "MySQL server detected"
        elif port == 5432:  # PostgreSQL
            service_info["postgresql_info"] = "PostgreSQL server detected"
        elif port == 27017:  # MongoDB
            service_info["mongodb_info"] = "MongoDB server detected"
        elif port == 1433:  # SQL Server
            service_info["mssql_info"] = "SQL Server detected"
        
        sock.close()
        
    except Exception as e:
        service_info["error"] = str(e)
    
    return service_info


def grab_generic_banner(ip, port):
    """Grab banner from generic services"""
    service_info = {}
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        
        # Try different approaches to get a banner
        try:
            # First, try to receive data immediately
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if banner.strip():
                service_info["banner"] = banner.strip()
        except:
            try:
                # Try sending HTTP request
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                sock.settimeout(3)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if response.strip():
                    service_info["banner"] = response.strip()[:200]  # Limit banner size
            except:
                pass
        
        sock.close()
        
    except Exception as e:
        service_info["error"] = str(e)
    
    return service_info


def extract_product_version_from_banner(banner):
    """Extract product and version from service banner"""
    if not banner:
        return None, None
    
    # Common patterns for product/version extraction
    patterns = [
        r'([A-Za-z][A-Za-z0-9_-]+)[/\s]+v?([0-9]+\.[0-9]+[0-9.]*)',
        r'([A-Za-z][A-Za-z0-9_-]+)[/\s]+([0-9]+\.[0-9]+[0-9.]*)',
        r'([A-Za-z]+)[/\s]+([0-9]+\.[0-9]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1), match.group(2)
    
    return None, None


def extract_title_from_html(html):
    """Extract title from HTML"""
    if not html:
        return None
    
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        return title_match.group(1).strip()
    
    return None


def detect_web_technologies(html, headers):
    """Detect web technologies from HTML and headers"""
    technologies = {}
    
    if not html:
        return technologies
    
    # CMS Detection
    cms_patterns = {
        'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
        'Drupal': [r'sites/default', r'drupal\.js', r'Drupal\.'],
        'Joomla': [r'joomla', r'option=com_', r'templates/system'],
        'Magento': [r'magento', r'skin/frontend', r'js/mage/'],
        'Shopify': [r'shopify', r'cdn\.shopify\.com']
    }
    
    for cms, patterns in cms_patterns.items():
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                technologies[cms] = {"categories": ["CMS"]}
                break
    
    # JavaScript Libraries
    js_patterns = {
        'jQuery': r'jquery[/-]([0-9.]+)',
        'Angular': r'angular[/-]([0-9.]+)',
        'React': r'react[/-]([0-9.]+)',
        'Vue.js': r'vue[/-]([0-9.]+)',
        'Bootstrap': r'bootstrap[/-]([0-9.]+)'
    }
    
    for lib, pattern in js_patterns.items():
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            technologies[lib] = {
                "categories": ["JavaScript Libraries"],
                "version": match.group(1)
            }
    
    # Server detection from headers
    if 'Server' in headers:
        server = headers['Server']
        technologies['Web Server'] = {
            "categories": ["Web Servers"],
            "version": server
        }
    
    return technologies


def discover_subdomains_comprehensive(target, results, max_workers=20):
    """Comprehensive subdomain discovery"""
    if is_ip_address(target):
        print_section("Subdomain Discovery Skipped")
        print(f"Target {target} is an IP address")
        return
    
    print_section(f"Discovering subdomains for {target}")
    
    subdomains = set()
    
    # Method 1: Common subdomain enumeration
    common_subdomains = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'blog',
        'shop', 'store', 'support', 'help', 'secure', 'vpn', 'remote', 'portal',
        'app', 'mobile', 'cdn', 'static', 'assets', 'img', 'images', 'media',
        'uploads', 'download', 'files', 'docs', 'beta', 'demo', 'backup',
        'old', 'new', 'test1', 'test2', 'dev1', 'dev2', 'staging1', 'staging2',
        'prod', 'production', 'live', 'internal', 'intranet', 'extranet',
        'vpn', 'mail2', 'email', 'webmail', 'mx', 'ns', 'ns1', 'ns2', 'dns',
        'ftp2', 'sftp', 'ssh', 'git', 'svn', 'cvs', 'repo', 'code', 'src'
    ]
    
    def check_subdomain(subdomain):
        full_domain = f"{subdomain}.{target}"
        try:
            ip = socket.gethostbyname(full_domain)
            return full_domain
        except:
            return None
    
    print(f"Testing {len(common_subdomains)} common subdomains...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        subdomain_futures = {executor.submit(check_subdomain, sub): sub for sub in common_subdomains}
        for future in as_completed(subdomain_futures):
            domain = future.result()
            if domain:
                subdomains.add(domain)
    
    # Method 2: Extract from SSL certificates
    for cert_info in results.get("ssl_certificates", []):
        cert_details = cert_info.get("details", {})
        if "extensions" in cert_details and "subjectAltName" in cert_details["extensions"]:
            alt_names = cert_details["extensions"]["subjectAltName"].split(", ")
            for alt_name in alt_names:
                if target in alt_name and alt_name not in subdomains:
                    subdomains.add(alt_name)
    
    results["subdomains"]["consolidated"] = sorted(list(subdomains))
    results["subdomains"]["count"] = len(subdomains)
    
    print(f"Found {len(subdomains)} subdomains: {list(subdomains)}")


def analyze_web_technologies_comprehensive(target, results):
    """Comprehensive web technology analysis"""
    print_section("Analyzing web technologies")
    
    protocols = ['https', 'http']
    
    for protocol in protocols:
        try:
            url = f"{protocol}://{target}"
            response = requests.get(url, timeout=10, verify=False,
                                    headers={'User-Agent': 'Mozilla/5.0 Tech Scanner'})
            
            tech_info = {
                "ip": results["host_info"].get("ip"),
                "port": 443 if protocol == 'https' else 80,
                "query": f"Web technology analysis for {target}"
            }
            
            # Detect technologies
            components = detect_web_technologies(response.text, response.headers)
            if components:
                tech_info["components"] = components
            
            results["web_technologies"].append(tech_info)
            break  # Success, no need to try other protocols
            
        except Exception as e:
            continue
    
    print(f"Technology analysis completed")


def analyze_security_headers_comprehensive(target, results):
    """Comprehensive security headers analysis"""
    print_section("Analyzing security headers")
    
    protocols = ['https', 'http']
    expected_security_headers = [
        'strict-transport-security',
        'content-security-policy',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy',
        'feature-policy'
    ]
    
    headers_found = set()
    
    for protocol in protocols:
        try:
            url = f"{protocol}://{target}"
            response = requests.get(url, timeout=10, verify=False,
                                    headers={'User-Agent': 'Mozilla/5.0 Security Scanner'})
            
            header_data = {
                "ip": results["host_info"].get("ip"),
                "port": 443 if protocol == 'https' else 80,
                "protocol": protocol
            }
            
            security_headers = {}
            all_headers = {}
            
            for name, value in response.headers.items():
                name_lower = name.lower()
                all_headers[name_lower] = value
                
                if name_lower in expected_security_headers:
                    security_headers[name_lower] = value
                    headers_found.add(name_lower)
            
            header_data["security_headers"] = security_headers
            header_data["all_headers"] = all_headers
            
            # Record server info if available
            if 'server' in all_headers:
                header_data["server"] = all_headers['server']
            
            results["security_headers"]["headers"].append(header_data)
            break  # Success
            
        except Exception as e:
            continue
    
    # Analyze which security headers are missing
    missing_headers = [h for h in expected_security_headers if h not in headers_found]
    
    results["security_headers"]["analysis"] = {
        "headers_found": list(headers_found),
        "headers_missing": missing_headers,
        "score": (len(headers_found) / len(expected_security_headers)) * 100
    }
    
    print(f"Security header analysis completed - Score: {results['security_headers']['analysis']['score']:.1f}%")


def check_vulnerabilities_comprehensive(target, ip, results):
    """Comprehensive vulnerability checking without Shodan"""
    print_section("Checking for vulnerabilities")
    
    vulnerabilities = []
    
    # Check services for known vulnerabilities
    for service in results.get("services", []):
        port = service.get("port")
        service_name = service.get("service", "")
        product = service.get("product", "")
        version = service.get("version", "")
        
        # Check for risky services
        risky_services = {
            21: "FTP service may allow anonymous access or brute force attacks",
            23: "Telnet provides unencrypted communication",
            135: "RPC service may be vulnerable to enumeration attacks", 
            139: "NetBIOS service may leak system information",
            445: "SMB service may be vulnerable to attacks like EternalBlue",
            1433: "SQL Server may have weak authentication",
            3306: "MySQL may have default credentials",
            3389: "RDP service is commonly targeted for brute force",
            5432: "PostgreSQL may have weak authentication",
            6379: "Redis may allow unauthenticated access",
            27017: "MongoDB may allow unauthenticated access"
        }
        
        if port in risky_services:
            vulnerabilities.append({
                "type": "risky_service",
                "port": port,
                "service": service_name,
                "description": risky_services[port],
                "severity": "Medium"
            })
        
        # Check for version-specific vulnerabilities
        if product and version:
            vuln_info = check_for_cve(product, version)
            if vuln_info:
                vulnerabilities.append({
                    "type": "version_vulnerability",
                    "port": port,
                    "product": product,
                    "version": version,
                    "description": vuln_info["cve_description"],
                    "severity": "High"
                })
    
    # Check SSL/TLS vulnerabilities
    for cert_info in results.get("ssl_certificates", []):
        cert = cert_info.get("details", {})
        
        # Check certificate expiration
        try:
            expires = datetime.strptime(cert['expires'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expires - datetime.utcnow()).days
            
            if days_left < 30:
                severity = "Critical" if days_left < 0 else "High" if days_left < 7 else "Medium"
                vulnerabilities.append({
                    "type": "ssl_certificate_expiry",
                    "port": cert_info.get("port"),
                    "days_remaining": days_left,
                    "description": f"SSL certificate expires in {days_left} days",
                    "severity": severity
                })
        except:
            pass
    
    results["vulnerabilities"] = vulnerabilities
    print(f"Found {len(vulnerabilities)} potential vulnerabilities")


def perform_active_web_scan_comprehensive(target, results):
    """Comprehensive active web scanning"""
    if is_ip_address(target):
        print_section("Active Web Scan Skipped")
        print(f"Target {target} is an IP address")
        return
    
    print_section("Performing comprehensive active web scan")
    
    try:
        # Use existing active scanner
        vulnerabilities = perform_active_web_scan(target)
        results["active_scan_vulnerabilities"] = vulnerabilities
        
        # Additional comprehensive checks
        check_exposed_files_comprehensive(target, results)
        check_web_vulnerabilities_comprehensive(target, results)
        
        print(f"Active web scan completed")
        
    except Exception as e:
        print(f"Error during active web scan: {e}")


def check_exposed_files_comprehensive(target, results):
    """Check for exposed files comprehensively"""
    print("Checking for exposed sensitive files...")
    
    protocols = ['https', 'http']
    sensitive_files = [
        '/.env', '/.git/config', '/.svn/entries', '/config.php', '/wp-config.php',
        '/database.yml', '/settings.py', '/config.json', '/config.xml',
        '/web.config', '/app.config', '/.htpasswd', '/.htaccess',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
        '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
        '/server-status', '/server-info', '/admin/', '/admin.php',
        '/backup/', '/backups/', '/dump/', '/dumps/',
        '/logs/', '/log/', '/tmp/', '/temp/'
    ]
    
    findings = []
    
    for protocol in protocols:
        for file_path in sensitive_files:
            try:
                url = f"{protocol}://{target}{file_path}"
                response = requests.get(url, timeout=5, verify=False,
                                        headers={'User-Agent': 'Mozilla/5.0 File Scanner'})
                
                if response.status_code == 200 and len(response.text) > 0:
                    # Verify it's not a custom 404 page
                    if not ("not found" in response.text.lower() or "404" in response.text):
                        severity = "Critical" if any(x in file_path for x in ['.env', 'config', '.git', '.svn', 'backup', 'dump']) else "Medium"
                        findings.append({
                            "pattern": file_path.replace('/', ''),
                            "ip": results["host_info"].get("ip"),
                            "port": 443 if protocol == 'https' else 80,
                            "url": url,
                            "severity": severity,
                            "description": f"Sensitive file exposed: {file_path}"
                        })
            except:
                continue
        
        if findings:  # If we found files, no need to try other protocol
            break
    
    results["exposed_files"]["findings"] = findings
    print(f"Found {len(findings)} potentially exposed files")


def check_web_vulnerabilities_comprehensive(target, results):
    """Check for web vulnerabilities comprehensively"""
    print("Checking for web application vulnerabilities...")
    
    web_vulns = []
    
    try:
        # Use existing web vulnerability checker but enhance it
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, verify=False,
                                        headers={'User-Agent': 'Mozilla/5.0 Vuln Scanner'})
                
                # Analyze response for vulnerabilities
                findings = analyze_http_response(url, 
                                                 {k.lower(): v for k, v in response.headers.items()}, 
                                                 response.text, 
                                                 response.status_code)
                
                web_vulns.extend(findings)
                break  # Success
                
            except Exception as e:
                continue
    except Exception as e:
        print(f"Error during web vulnerability check: {e}")
    
    results["web_vulnerabilities"] = web_vulns
    print(f"Found {len(web_vulns)} web vulnerabilities")


def main():
    # Parse command line arguments (optional)
    parser = argparse.ArgumentParser(description='Web Reconnaissance Tool - With or Without Shodan')
    parser.add_argument('-d', '--domain', help='Target domain or IP to gather intelligence on')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--shodan', action='store_true', help='Use Shodan API for reconnaissance')
    parser.add_argument('--no-shodan', action='store_true', help='Run without Shodan API (active scanning only)')
    parser.add_argument('--all', action='store_true', help='Run all available checks')
    parser.add_argument('--basic', action='store_true', help='Basic information only (faster)')
    parser.add_argument('--subdomains', action='store_true', help='Collect subdomains')
    parser.add_argument('--tech', action='store_true', help='Identify web technologies')
    parser.add_argument('--headers', action='store_true', help='Analyze security headers')
    parser.add_argument('--vulns', action='store_true', help='Identify potential security issues')
    parser.add_argument('--webvulns', action='store_true', help='Check for common web vulnerabilities')
    parser.add_argument('--activescan', action='store_true', help='Perform active web vulnerability scanning (sends requests to target)')
    parser.add_argument('--files', action='store_true', help='Search for exposed files')
    parser.add_argument('--ssl', action='store_true', help='Analyze SSL certificates')
    parser.add_argument('--errors', action='store_true', help='Collect HTTP error responses')
    parser.add_argument('--similar', action='store_true', help='Find similar hosts')
    parser.add_argument('--related', action='store_true', help='Find related hosts')
    parser.add_argument('--dns', action='store_true', help='Comprehensive DNS analysis')
    parser.add_argument('--whois', action='store_true', help='WHOIS information')
    parser.add_argument('--certs', action='store_true', help='Certificate Transparency logs')
    parser.add_argument('--cloud', action='store_true', help='Cloud provider identification')
    parser.add_argument('--archive', action='store_true', help='Web archive history')
    parser.add_argument('--advanced-cms', action='store_true', help='Advanced CMS/framework detection')
    parser.add_argument('--api-discovery', action='store_true', help='API endpoint discovery')
    parser.add_argument('--limit', type=int, default=5, help='Limit number of results per search query (default: 5)')
    parser.add_argument('--pretty', action='store_true', help='Pretty print the JSON output')
    parser.add_argument('--interactive', action='store_true', help='Use interactive mode (prompt for options)')
    
    args = parser.parse_args()
    
    # Validate dependencies for specific features
    if args.dns and not DNS_AVAILABLE:
        print("Error: --dns requires dnspython. Install with: pip install dnspython")
        sys.exit(1)
    
    if args.whois and not WHOIS_AVAILABLE:
        print("Error: --whois requires python-whois. Install with: pip install python-whois")
        sys.exit(1)
    
    # Determine if we're in interactive mode
    interactive_mode = args.interactive or not args.domain
    
    print_banner("Web Reconnaissance Tool")
    print("This tool can gather intelligence using Shodan API or perform active scanning without Shodan")
    
    # Determine scanning mode
    use_shodan = False
    if args.shodan:
        use_shodan = True
    elif args.no_shodan:
        use_shodan = False
    elif interactive_mode:
        print("\nChoose scanning mode:")
        print("1. Use Shodan API (requires API key)")
        print("2. Active scanning only (no Shodan API required)")
        
        mode_choice = get_user_input("Enter mode (1-2)", "2")
        use_shodan = (mode_choice == "1")
    else:
        # Default behavior - check if Shodan API key is available
        shodan_api_key = os.getenv("SHODAN_API_KEY")
        if shodan_api_key:
            print("Shodan API key found - using Shodan mode")
            use_shodan = True
        else:
            print("No Shodan API key found - using active scanning mode")
            use_shodan = False
    
    # Initialize Shodan API if needed
    api = None
    if use_shodan:
        shodan_api_key = os.getenv("SHODAN_API_KEY")
        if not shodan_api_key:
            print("Error: Shodan API key not found. Please set the SHODAN_API_KEY environment variable.")
            print("Or run with --no-shodan flag to use active scanning only.")
            sys.exit(1)
        
        api = shodan.Shodan(shodan_api_key)
        
        # Check API info and credits
        try:
            info = api.info()
            print(f"Shodan API Plan: {info['plan']}")
            print(f"Query Credits Available: {info['query_credits']} / {info['usage_limits']['query_credits']}")
            print(f"Scan Credits Available: {info['scan_credits']} / {info['usage_limits']['scan_credits']}")
        except Exception as e:
            print(f"Error connecting to Shodan API: {e}")
            print("Falling back to active scanning mode...")
            use_shodan = False
            api = None
    else:
        print("Running in active scanning mode (no Shodan API)")
        info = None
    
    # Set parameters based on mode (interactive or command line)
    if interactive_mode:
        # Get domain from user
        target = get_user_input("Enter target domain or IP (e.g. example.com or 1.2.3.4)")
        if not target:
            print("Error: Target is required.")
            sys.exit(1)
        
        # Process input to ensure we have a clean domain/IP
        if not is_ip_address(target):
            target = extract_hostname(target)
        
        # Set the output file name
        safe_target = target.replace('/', '_').replace(':', '_')
        default_output = f"{safe_target}_shodan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_file = get_user_input("Enter output filename", default_output)
        
        # Ask about scan type
        if use_shodan:
            print("\nShodan API mode - Select scan type:")
            print("1. Basic scan (basic host information only)")
            print("2. Standard scan (basic + subdomains, technologies, headers, SSL)")
            print("3. Full scan (all Shodan checks including security analysis)")
            print("4. Custom scan (select individual modules)")
        else:
            print("\nActive scanning mode - Select scan type:")
            print("1. Basic scan (SSL analysis and security headers only)")
            print("2. Standard scan (active vulnerability scanning + SSL analysis)")
            print("3. Full scan (comprehensive active scanning)")
            print("4. Custom scan (select individual modules)")
        
        scan_type = get_user_input("Enter scan type (1-4)", "2")
        
        # Ask for result limit (only for Shodan mode)
        if use_shodan:
            result_limit = int(get_user_input("Number of results per search query (default: 5, max recommended: 20)", "5"))
        else:
            result_limit = 5  # Default for active scanning
        
        if use_shodan:
            # Shodan mode scan types
            if scan_type == "1":  # Basic scan
                run_basic = True
                run_subdomains = False
                run_tech = False
                run_headers = False
                run_ssl = False
                run_vulns = False
                run_webvulns = False
                run_activescan = False
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
                run_dns = False
                run_whois = False
                run_certs = False
                run_cloud = False
                run_archive = False
                run_advanced_cms = False
                run_api_discovery = False
            elif scan_type == "2":  # Standard scan
                run_basic = True
                run_subdomains = True
                run_tech = True
                run_headers = True
                run_ssl = True
                run_vulns = False
                run_webvulns = True
                run_activescan = False
                run_files = False
                run_errors = True
                run_similar = True
                run_related = True
                run_dns = False
                run_whois = False
                run_certs = False
                run_cloud = False
                run_archive = False
                run_advanced_cms = False
                run_api_discovery = False
            elif scan_type == "3":  # Full scan
                run_basic = True
                run_subdomains = True
                run_tech = True
                run_headers = True
                run_ssl = True
                run_vulns = True
                run_webvulns = True
                run_activescan = True
                run_files = True
                run_errors = True
                run_similar = True
                run_related = True
                run_dns = True
                run_whois = True
                run_certs = True
                run_cloud = True
                run_archive = True
                run_advanced_cms = True
                run_api_discovery = True
            else:  # Custom scan
                print("\nSelect which Shodan modules to run:")
                run_basic = True  # Always run basic checks
                run_subdomains = get_yes_no_input("Collect subdomains?", "y")
                run_tech = get_yes_no_input("Identify web technologies?", "y")
                run_headers = get_yes_no_input("Analyze security headers?", "y")
                run_ssl = get_yes_no_input("Analyze SSL certificates?", "y")
                run_vulns = get_yes_no_input("Identify potential security issues in infrastructure?", "y")
                run_webvulns = get_yes_no_input("Check for common web vulnerabilities?", "y")
                run_activescan = get_yes_no_input("Perform active web vulnerability scanning?", "n")
                run_files = get_yes_no_input("Search for exposed files?", "y")
                run_errors = get_yes_no_input("Collect HTTP error responses?", "y")
                run_similar = get_yes_no_input("Find similar hosts?", "y")
                run_related = get_yes_no_input("Find related hosts?", "y")
                run_dns = get_yes_no_input("Perform comprehensive DNS analysis?", "y")
                run_whois = get_yes_no_input("Get WHOIS information?", "y")
                run_certs = get_yes_no_input("Check Certificate Transparency logs?", "y")
                run_cloud = get_yes_no_input("Identify cloud provider?", "y")
                run_archive = get_yes_no_input("Check web archive history?", "y")
                run_advanced_cms = get_yes_no_input("Advanced CMS/framework detection?", "y")
                run_api_discovery = get_yes_no_input("Discover API endpoints?", "y")
        else:
            # Active scanning mode scan types
            if scan_type == "1":  # Basic scan
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = True
                run_ssl = True
                run_vulns = False
                run_webvulns = False
                run_activescan = False
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
            elif scan_type == "2":  # Standard scan
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = True
                run_ssl = True
                run_vulns = False
                run_webvulns = False
                run_activescan = True
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
            elif scan_type == "3":  # Full scan
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = True
                run_ssl = True
                run_vulns = False
                run_webvulns = False
                run_activescan = True
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
            else:  # Custom scan
                print("\nSelect which active scanning modules to run:")
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = get_yes_no_input("Analyze security headers?", "y")
                run_ssl = get_yes_no_input("Analyze SSL certificates?", "y")
                run_vulns = False  # Not available without Shodan
                run_webvulns = False  # Limited without Shodan
                run_activescan = get_yes_no_input("Perform active web vulnerability scanning?", "y")
                run_files = False  # Not available without Shodan
                run_errors = False  # Not available without Shodan
                run_similar = False  # Not available without Shodan
                run_related = False  # Not available without Shodan
        
        # Ask about JSON formatting
        pretty_print = get_yes_no_input("Pretty print the JSON output?", "y")
    else:
        # Use command line arguments
        target = args.domain
        result_limit = args.limit
        
        # Process input to ensure we have a clean domain/IP
        if not is_ip_address(target):
            target = extract_hostname(target)
        
        # Set the output file name
        if args.output:
            output_file = args.output
        else:
            # Sanitize domain name for filename
            safe_target = target.replace('/', '_').replace(':', '_')
            output_file = f"{safe_target}_shodan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Get the module flags
        if use_shodan:
            # Shodan mode
            if args.all:  # Full scan
                run_basic = True
                run_subdomains = True
                run_tech = True
                run_headers = True
                run_ssl = True
                run_vulns = True
                run_webvulns = True
                run_activescan = True
                run_files = True
                run_errors = True
                run_similar = True
                run_related = True
                run_dns = True
                run_whois = True
                run_certs = True
                run_cloud = True
                run_archive = True
                run_advanced_cms = True
                run_api_discovery = True
            elif args.basic:  # Basic scan only
                run_basic = True
                run_subdomains = False
                run_tech = False
                run_headers = False
                run_ssl = False
                run_vulns = False
                run_webvulns = False
                run_activescan = False
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
                run_dns = False
                run_whois = False
                run_certs = False
                run_cloud = False
                run_archive = False
                run_advanced_cms = False
                run_api_discovery = False
            else:  # Individual modules
                run_basic = True  # Always run basic checks in Shodan mode
                run_subdomains = args.subdomains
                run_tech = args.tech
                run_headers = args.headers
                run_ssl = args.ssl
                run_vulns = args.vulns
                run_webvulns = args.webvulns
                run_activescan = args.activescan
                run_files = args.files
                run_errors = args.errors
                run_similar = args.similar
                run_related = args.related
                run_dns = args.dns
                run_whois = args.whois
                run_certs = args.certs
                run_cloud = args.cloud
                run_archive = args.archive
                run_advanced_cms = args.advanced_cms
                run_api_discovery = args.api_discovery
                
                # If no specific modules selected, do standard scan
                if not any([args.subdomains, args.tech, args.headers, args.ssl, args.vulns, 
                           args.webvulns, args.activescan, args.files, args.errors, args.similar, args.related,
                           args.dns, args.whois, args.certs, args.cloud, args.archive, args.advanced_cms, args.api_discovery]):
                    run_subdomains = True
                    run_tech = True
                    run_headers = True
                    run_ssl = True
                    run_webvulns = True
                    run_activescan = False  # Default to off for active scanning
                    run_errors = True
                    run_similar = True
                    run_related = True
        else:
            # Active scanning mode (no Shodan)
            if args.all:  # Full scan
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = True
                run_ssl = True
                run_vulns = False
                run_webvulns = False
                run_activescan = True
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
                run_dns = True
                run_whois = True
                run_certs = True
                run_cloud = True
                run_archive = True
                run_advanced_cms = True
                run_api_discovery = True
            elif args.basic:  # Basic scan only
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = True
                run_ssl = True
                run_vulns = False
                run_webvulns = False
                run_activescan = False
                run_files = False
                run_errors = False
                run_similar = False
                run_related = False
                run_dns = False
                run_whois = False
                run_certs = False
                run_cloud = False
                run_archive = False
                run_advanced_cms = False
                run_api_discovery = False
            else:  # Individual modules (limited in non-Shodan mode)
                run_basic = False
                run_subdomains = False
                run_tech = False
                run_headers = args.headers if args.headers else True  # Default to true
                run_ssl = args.ssl if args.ssl else True  # Default to true
                run_vulns = False  # Not available without Shodan
                run_webvulns = False  # Limited without Shodan
                run_activescan = args.activescan
                run_files = False  # Not available without Shodan
                run_errors = False  # Not available without Shodan
                run_similar = False  # Not available without Shodan
                run_related = False  # Not available without Shodan
                run_dns = args.dns
                run_whois = args.whois
                run_certs = args.certs
                run_cloud = args.cloud
                run_archive = args.archive
                run_advanced_cms = args.advanced_cms
                run_api_discovery = args.api_discovery
                
                # If activescan not specified, default to true for non-Shodan mode
                if not args.activescan and not any([args.headers, args.ssl]):
                    run_activescan = True
        
        pretty_print = args.pretty
    
    # Initialize the results dictionary
    results = {
        "metadata": {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "scanning_mode": "shodan" if use_shodan else "active_only",
            "modules": {
                "basic": run_basic,
                "subdomains": run_subdomains,
                "technologies": run_tech,
                "security_headers": run_headers,
                "ssl": run_ssl,
                "vulnerabilities": run_vulns,
                "web_vulnerabilities": run_webvulns,
                "active_scanning": run_activescan,
                "exposed_files": run_files,
                "http_errors": run_errors,
                "similar_hosts": run_similar,
                "related_hosts": run_related,
                "dns_analysis": run_dns,
                "whois_info": run_whois,
                "certificate_transparency": run_certs,
                "cloud_provider": run_cloud,
                "web_archive": run_archive,
                "advanced_cms_detection": run_advanced_cms,
                "api_discovery": run_api_discovery
            }
        }
    }
    
    try:
        if use_shodan and info:
            results["metadata"]["api_info"] = {
                "plan": info['plan'],
                "query_credits_start": info['query_credits'],
                "scan_credits_start": info['scan_credits']
            }
        
        # Resolve domain to IP if needed
        if is_ip_address(target):
            ip = target
            print(f"Target {target} is an IP address, no resolution needed.")
        else:
            ip = resolve_domain(target)
            if not ip:
                results["error"] = "Could not resolve domain"
                save_results(results, output_file, pretty_print)
                sys.exit(1)
        
        results["metadata"]["ip"] = ip
        
        if use_shodan:
            print_banner(f"Starting Shodan reconnaissance on {target} ({ip})")
        else:
            print_banner(f"Starting active reconnaissance on {target} ({ip})")
        
        # Get the result limit from arguments
        result_limit = args.limit
        
        # Run selected modules and collect results
        if use_shodan and run_basic:
            domain_info = collect_domain_info(api, target, ip)
            results.update(domain_info)
        
        if use_shodan and run_related:
            related_hosts = collect_related_hosts(api, target, result_limit)
            results.update(related_hosts)
        
        if use_shodan and run_ssl:
            ssl_info = collect_ssl_information(api, target, result_limit)
            results.update(ssl_info)
        elif not use_shodan and run_ssl:
            # Basic SSL analysis without Shodan
            ssl_info = perform_basic_ssl_analysis(target)
            results.update(ssl_info)
        
        if use_shodan and run_tech:
            tech_info = collect_web_technologies(api, target, ip)
            results.update(tech_info)
        
        if use_shodan and run_headers:
            header_info = collect_security_headers(api, target, ip, result_limit)
            results.update(header_info)
        elif not use_shodan and run_headers:
            # Basic header analysis without Shodan
            header_info = perform_basic_header_analysis(target)
            results.update(header_info)
        
        if use_shodan and run_vulns:
            vuln_info = collect_vulnerabilities(api, ip, result_limit)
            results.update(vuln_info)
            
        if use_shodan and run_webvulns:
            webvuln_info = check_web_vulnerabilities(api, target, ip, result_limit)
            results.update(webvuln_info)
            
        if run_activescan and not is_ip_address(target):
            active_scan_info = perform_active_scanning(target)
            results.update(active_scan_info)
        
        if use_shodan and run_subdomains:
            subdomain_info = collect_subdomains(api, target, result_limit)
            results.update(subdomain_info)
        
        if use_shodan and run_files:
            file_info = collect_exposed_files(api, target, ip)
            results.update(file_info)
        
        if use_shodan and run_errors:
            error_info = collect_http_errors(api, target, ip)
            results.update(error_info)
        
        if use_shodan and run_similar:
            similar_hosts = collect_similar_hosts(api, ip, result_limit)
            results.update(similar_hosts)
        
        # New enhanced capabilities
        if run_dns:
            print_section("DNS Analysis")
            dns_info = get_comprehensive_dns_records(target)
            results["dns_analysis"] = dns_info
        
        if run_whois:
            print_section("WHOIS Information")
            whois_info = get_whois_information(target)
            results["whois_info"] = whois_info
        
        if run_certs:
            print_section("Certificate Transparency")
            cert_info = check_certificate_transparency_logs(target)
            results["certificate_transparency"] = cert_info
        
        if run_cloud:
            print_section("Cloud Provider Detection")
            cloud_info = check_cloud_provider(ip)
            results["cloud_provider"] = cloud_info
        
        if run_archive:
            print_section("Web Archive History")
            archive_info = check_web_archive_history(target)
            results["web_archive"] = archive_info
        
        if run_advanced_cms:
            print_section("Advanced CMS Detection")
            cms_info = check_advanced_cms_detection(target)
            results["advanced_cms_detection"] = cms_info
        
        if run_api_discovery:
            print_section("API Endpoint Discovery")
            api_info = check_api_endpoints(target)
            results["api_endpoints"] = api_info
        
        # Show final credit usage (only for Shodan mode)
        if use_shodan and api and info:
            try:
                final_info = api.info()
                results["metadata"]["api_info"]["query_credits_end"] = final_info['query_credits']
                results["metadata"]["api_info"]["scan_credits_end"] = final_info['scan_credits']
                results["metadata"]["api_info"]["credits_used"] = info['query_credits'] - final_info['query_credits']
                
                print_banner("Query Credits Summary")
                print(f"Starting query credits: {info['query_credits']}")
                print(f"Remaining query credits: {final_info['query_credits']}")
                print(f"Used in this script: {info['query_credits'] - final_info['query_credits']}")
            except Exception as e:
                print(f"Error retrieving final API info: {e}")
        else:
            # Comprehensive no-Shodan scanning mode
            print_banner("Starting Comprehensive No-Shodan Scan")
            print("This mode replicates all Shodan functionality using alternative methods")
            
            # Override results with comprehensive scan results
            max_workers = 20  # Default threading
            if interactive_mode:
                max_workers = int(get_user_input("Number of threads for scanning", "20"))
            
            comprehensive_results = perform_comprehensive_noshodan_scan(target, max_workers)
            
            # Merge comprehensive results with existing metadata
            for key, value in comprehensive_results.items():
                results[key] = value
            
            print_banner("Scan Completed")
            print("Comprehensive no-Shodan scanning completed with full information gathering")
        
        # Save results to file
        save_results(results, output_file, pretty_print)
    
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        results["error"] = f"Shodan API Error: {str(e)}"
        save_results(results, output_file, pretty_print)
    except Exception as e:
        print(f"Error: {e}")
        results["error"] = f"Error: {str(e)}"
        save_results(results, output_file, pretty_print)


if __name__ == "__main__":
    main()
