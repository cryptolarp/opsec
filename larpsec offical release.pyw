import customtkinter as ctk
import requests
import json
import threading
import time
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import re
import csv
import os
import sys
import queue
import base64
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import webbrowser
import socket
import ipaddress
import subprocess
import dns.resolver
import hashlib
import whois
from email_validator import validate_email, EmailNotValidError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import warnings
warnings.filterwarnings('ignore')

# ==================== TOKEN STORAGE ====================
class TokenStorage:
    """Secure token storage using encryption"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".discord_exporter"
        self.config_dir.mkdir(exist_ok=True)
        self.token_file = self.config_dir / "token.enc"
        self.key_file = self.config_dir / "key.key"
        self.cipher = None
        self.load_or_create_key()
    
    def load_or_create_key(self):
        """Load existing key or create a new one"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            import uuid
            machine_id = str(uuid.getnode())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'discord_exporter_salt',
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
            with open(self.key_file, 'wb') as f:
                f.write(key)
        
        self.cipher = Fernet(key)
    
    def save_token(self, token):
        if token:
            encrypted = self.cipher.encrypt(token.encode())
            with open(self.token_file, 'wb') as f:
                f.write(encrypted)
            return True
        return False
    
    def load_token(self):
        if self.token_file.exists():
            try:
                with open(self.token_file, 'rb') as f:
                    encrypted = f.read()
                decrypted = self.cipher.decrypt(encrypted)
                return decrypted.decode()
            except:
                return None
        return None
    
    def clear_token(self):
        if self.token_file.exists():
            self.token_file.unlink()


# ==================== IP LOOKUP ====================
class IPInformationGatherer:
    """Gather comprehensive IP information"""
    
    def __init__(self, ip_address: str):
        self.ip = ip_address
        self.results = {}
        
    def validate_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.ip)
            return True
        except ValueError:
            return False
    
    def get_ip_type(self) -> str:
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if ip_obj.is_private:
                return "Private"
            elif ip_obj.is_global:
                return "Public"
            elif ip_obj.is_loopback:
                return "Loopback"
            elif ip_obj.is_multicast:
                return "Multicast"
            elif ip_obj.is_reserved:
                return "Reserved"
            else:
                return "Unknown"
        except:
            return "Invalid IP"
    
    def get_hostname(self) -> str:
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            return hostname
        except socket.herror:
            return "No hostname found"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_ip_api_info(self) -> Dict:
        try:
            response = requests.get(f'http://ip-api.com/json/{self.ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'isp': data.get('isp', 'Unknown'),
                        'organization': data.get('org', 'Unknown'),
                        'as_number': data.get('as', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'zip_code': data.get('zip', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'latitude': data.get('lat', 'Unknown'),
                        'longitude': data.get('lon', 'Unknown'),
                        'mobile': data.get('mobile', False),
                        'proxy': data.get('proxy', False),
                        'hosting': data.get('hosting', False)
                    }
            return {'error': 'Failed to get IP API info'}
        except Exception as e:
            return {'error': f'IP API error: {str(e)}'}
    
    def get_ipwhois_io_info(self) -> Dict:
        try:
            response = requests.get(f'https://ipwhois.io/json/{self.ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if not data.get('success') == False:
                    return {
                        'isp': data.get('isp', 'Unknown'),
                        'organization': data.get('org', 'Unknown'),
                        'as_number': data.get('asn', 'Unknown'),
                        'as_name': data.get('as', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('country_code', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('latitude', 'Unknown'),
                        'longitude': data.get('longitude', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'currency': data.get('currency', 'Unknown'),
                        'is_eu': data.get('is_eu', False)
                    }
            return {'error': 'Failed to get ipwhois.io info'}
        except Exception as e:
            return {'error': f'ipwhois.io error: {str(e)}'}
    
    def get_rdap_info(self) -> Dict:
        try:
            response = requests.get(f'https://rdap.arin.net/registry/ip/{self.ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self.parse_rdap_data(data)
            
            response = requests.get(f'https://rdap.db.ripe.net/ip/{self.ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self.parse_rdap_data(data)
            
            response = requests.get(f'https://rdap.apnic.net/ip/{self.ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return self.parse_rdap_data(data)
            
            return {'error': 'RDAP lookup failed'}
        except Exception as e:
            return {'error': f'RDAP error: {str(e)}'}
    
    def parse_rdap_data(self, data: Dict) -> Dict:
        rdap_dict = {}
        try:
            if 'handle' in data:
                rdap_dict['handle'] = data['handle']
            if 'name' in data:
                rdap_dict['name'] = data['name']
            if 'entities' in data:
                for entity in data['entities']:
                    if entity.get('roles') and 'registrar' in entity.get('roles', []):
                        if 'vcardArray' in entity:
                            vcard = entity['vcardArray'][1]
                            for item in vcard:
                                if item[0] == 'fn':
                                    rdap_dict['organization'] = item[3]
                                elif item[0] == 'org':
                                    rdap_dict['organization'] = item[3]
            if 'startAddress' in data and 'endAddress' in data:
                rdap_dict['ip_range'] = f"{data['startAddress']} - {data['endAddress']}"
            if 'country' in data:
                rdap_dict['country'] = data['country']
            if 'events' in data:
                for event in data['events']:
                    if event.get('eventAction') == 'registration':
                        rdap_dict['registration_date'] = event.get('eventDate')
                    elif event.get('eventAction') == 'last changed':
                        rdap_dict['last_changed'] = event.get('eventDate')
        except Exception as e:
            rdap_dict['error'] = f'Error parsing RDAP: {str(e)}'
        return rdap_dict if rdap_dict else {'error': 'Could not parse RDAP data'}
    
    def get_dns_info(self) -> Dict:
        dns_info = {}
        record_types = ['PTR', 'MX', 'NS']
        for record_type in record_types:
            try:
                if record_type == 'PTR':
                    try:
                        hostname = socket.gethostbyaddr(self.ip)[0]
                        dns_info[record_type] = [hostname]
                    except:
                        dns_info[record_type] = ['Not found']
                else:
                    resolver = dns.resolver.Resolver()
                    answers = resolver.resolve(self.ip, record_type)
                    dns_info[record_type] = [str(answer) for answer in answers]
            except Exception:
                dns_info[record_type] = ['Not found']
        return dns_info
    
    def get_reverse_dns(self) -> List[str]:
        try:
            reverse_dns = socket.gethostbyaddr(self.ip)
            return list(reverse_dns)
        except:
            return ['No reverse DNS found']
    
    def ping_ip(self) -> Dict:
        try:
            import platform
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', self.ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            output_lines = result.stdout.split('\n')
            relevant_output = [line for line in output_lines if 'time=' in line.lower() or 'ttl=' in line.lower()]
            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'output': relevant_output[0] if relevant_output else result.stdout[:200]
            }
        except Exception as e:
            return {'error': f'Ping failed: {str(e)}'}
    
    def get_all_info(self) -> Dict:
        if not self.validate_ip():
            return {'error': 'Invalid IP address provided'}
        
        self.results = {
            'ip_address': self.ip,
            'ip_type': self.get_ip_type(),
            'hostname': self.get_hostname(),
            'ip_api': self.get_ip_api_info(),
            'ipwhois': self.get_ipwhois_io_info(),
            'rdap': self.get_rdap_info(),
            'dns_records': self.get_dns_info(),
            'reverse_dns': self.get_reverse_dns(),
            'ping_result': self.ping_ip()
        }
        return self.results


# ==================== EMAIL ANALYZER ====================
class EmailAnalyzer:
    def __init__(self):
        self.results = {}
    
    def analyze_email(self, email_address):
        results = {
            'email': email_address,
            'validation': {},
            'domain_analysis': {},
            'security': {},
            'data_breaches': {},
            'gravatar': {}
        }
        
        results['validation'] = self._validate_email(email_address)
        domain = email_address.split('@')[1]
        results['domain_analysis'] = self._analyze_domain(domain)
        results['security'] = self._check_email_security(email_address)
        results['data_breaches'] = self._check_breaches(email_address)
        results['gravatar'] = self._check_gravatar(email_address)
        results['additional_info'] = self._get_email_intelligence(email_address)
        
        self.results = results
        return results
    
    def _validate_email(self, email_address):
        validation = {'format_valid': False, 'mx_records_exist': False, 'mx_records': [], 'disposable': False, 'free_provider': False}
        try:
            valid = validate_email(email_address)
            email_address = valid.email
            validation['format_valid'] = True
        except EmailNotValidError as e:
            validation['format_valid'] = False
            validation['error'] = str(e)
            return validation
        
        domain = email_address.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            validation['mx_records_exist'] = True
            validation['mx_records'] = [str(record.exchange) for record in mx_records]
        except:
            pass
        
        disposable_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com']
        validation['disposable'] = domain in disposable_domains
        
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'protonmail.com']
        validation['free_provider'] = domain in free_providers
        return validation
    
    def _analyze_domain(self, domain):
        analysis = {'domain': domain, 'whois_info': {}, 'age_days': None, 'has_website': False, 'website_status': None, 'ip_addresses': []}
        try:
            w = whois.whois(domain)
            analysis['whois_info'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'organization': w.org
            }
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                analysis['age_days'] = (datetime.now() - creation_date).days
        except:
            analysis['whois_info']['error'] = "Could not retrieve WHOIS info"
        
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            analysis['has_website'] = True
            analysis['website_status'] = response.status_code
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            analysis['ip_addresses'] = ip_addresses
        except:
            pass
        return analysis
    
    def _check_email_security(self, email_address):
        security = {'spf_record': False, 'dmarc_record': False}
        domain = email_address.split('@')[1]
        try:
            spf = dns.resolver.resolve(domain, 'TXT')
            for record in spf:
                if 'v=spf1' in str(record):
                    security['spf_record'] = True
                    break
        except:
            pass
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc:
                if 'v=DMARC1' in str(record):
                    security['dmarc_record'] = True
                    break
        except:
            pass
        return security
    
    def _check_breaches(self, email_address):
        breaches = {'breached': False, 'breach_count': 0, 'breaches': []}
        try:
            response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_address}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                breaches['breached'] = True
                breaches['breach_count'] = len(data)
                breaches['breaches'] = [{'name': breach['Name'], 'date': breach['BreachDate']} for breach in data[:5]]
            elif response.status_code == 404:
                breaches['breached'] = False
        except:
            breaches['error'] = "Could not check breaches"
        return breaches
    
    def _check_gravatar(self, email_address):
        gravatar = {'has_gravatar': False, 'avatar_url': None, 'name': None}
        email_hash = hashlib.md5(email_address.lower().encode()).hexdigest()
        gravatar['avatar_url'] = f"https://www.gravatar.com/avatar/{email_hash}"
        try:
            response = requests.get(f"https://www.gravatar.com/{email_hash}.json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'entry' in data and data['entry']:
                    gravatar['has_gravatar'] = True
                    gravatar['name'] = data['entry'][0].get('displayName', '')
        except:
            pass
        return gravatar
    
    def _get_email_intelligence(self, email_address):
        username = email_address.split('@')[0]
        domain = email_address.split('@')[1]
        possible_name = re.sub(r'[._-]', ' ', username)
        return {'possible_names': [possible_name], 'common_variations': [f"{username}.work@{domain}", f"{username}1@{domain}"]}


# ==================== COMPREHENSIVE PLATFORM LIST ====================
PLATFORMS = {
    'Twitter (X)': {'url': 'https://twitter.com/{}', 'not_found_indicators': ['this account doesn’t exist', 'page not found'], 'icon': '🐦', 'color': '#1DA1F2'},
    'Instagram': {'url': 'https://www.instagram.com/{}/', 'not_found_indicators': ['sorry, this page isn\'t available', 'page not found'], 'icon': '📸', 'color': '#E4405F'},
    'TikTok': {'url': 'https://www.tiktok.com/@{}', 'not_found_indicators': ['couldn\'t find this account'], 'icon': '🎵', 'color': '#000000'},
    'Reddit': {'url': 'https://www.reddit.com/user/{}', 'api_url': 'https://www.reddit.com/user/{}/about.json', 'detection_type': 'json_api', 'icon': '🤖', 'color': '#FF4500'},
    'Facebook': {'url': 'https://www.facebook.com/{}', 'not_found_indicators': ['content isn\'t available'], 'icon': '👤', 'color': '#1877F2'},
    'LinkedIn': {'url': 'https://www.linkedin.com/in/{}', 'not_found_indicators': ['page not found'], 'icon': '💼', 'color': '#0A66C2'},
    'Snapchat': {'url': 'https://www.snapchat.com/add/{}', 'not_found_indicators': ['couldn\'t find'], 'icon': '👻', 'color': '#FFFC00'},
    'Pinterest': {'url': 'https://www.pinterest.com/{}/', 'not_found_indicators': ['couldn\'t find that page'], 'icon': '📌', 'color': '#BD081C'},
    'Tumblr': {'url': 'https://{}.tumblr.com', 'detection_type': 'status_code', 'icon': '📓', 'color': '#36465D'},
    'Threads': {'url': 'https://www.threads.net/@{}', 'not_found_indicators': ['page isn\'t available'], 'icon': '🧵', 'color': '#000000'},
    'Bluesky': {'url': 'https://bsky.app/profile/{}', 'not_found_indicators': ['not found'], 'icon': '🦋', 'color': '#1185FE'},
    'Mastodon': {'url': 'https://mastodon.social/@{}', 'not_found_indicators': ['could not be found'], 'icon': '🐘', 'color': '#6364FF'},
    'Twitch': {'url': 'https://www.twitch.tv/{}', 'not_found_indicators': ['channel not found'], 'icon': '🎮', 'color': '#9146FF'},
    'Steam': {'url': 'https://steamcommunity.com/id/{}', 'not_found_indicators': ['could not be found'], 'icon': '🎮', 'color': '#171A21'},
    'Roblox': {'url': 'https://www.roblox.com/user.aspx?username={}', 'detection_type': 'status_code', 'icon': '🔲', 'color': '#FB4226'},
    'GitHub': {'url': 'https://github.com/{}', 'api_url': 'https://api.github.com/users/{}', 'detection_type': 'json_api', 'icon': '💻', 'color': '#181717'},
    'GitLab': {'url': 'https://gitlab.com/{}', 'not_found_indicators': ['not found'], 'icon': '🦊', 'color': '#FC6D26'},
    'YouTube': {'url': 'https://www.youtube.com/@{}', 'not_found_indicators': ['this page isn\'t available'], 'icon': '📺', 'color': '#FF0000'},
    'Medium': {'url': 'https://medium.com/@{}', 'not_found_indicators': ['not found'], 'icon': '📝', 'color': '#00AB6C'},
    'SoundCloud': {'url': 'https://soundcloud.com/{}', 'not_found_indicators': ['not found'], 'icon': '🎵', 'color': '#FF5500'},
    'Spotify': {'url': 'https://open.spotify.com/user/{}', 'not_found_indicators': ['not found'], 'icon': '🎧', 'color': '#1DB954'},
    'Telegram': {'url': 'https://t.me/{}', 'not_found_indicators': ['username doesn\'t exist'], 'icon': '📱', 'color': '#26A5E4'},
    'Discord': {'url': 'https://discord.com/users/{}', 'not_found_indicators': ['non-existent'], 'icon': '💬', 'color': '#5865F2'},
    'Quora': {'url': 'https://www.quora.com/profile/{}', 'not_found_indicators': ['not found'], 'icon': '❓', 'color': '#B92B27'},
    'Imgur': {'url': 'https://imgur.com/user/{}', 'not_found_indicators': ['not found'], 'icon': '🖼️', 'color': '#1BB76E'},
    'Patreon': {'url': 'https://www.patreon.com/{}', 'not_found_indicators': ['not found'], 'icon': '🎭', 'color': '#FF424D'},
    'Fiverr': {'url': 'https://www.fiverr.com/{}', 'not_found_indicators': ['not found'], 'icon': '💼', 'color': '#1DBF73'},
    'Keybase': {'url': 'https://keybase.io/{}', 'not_found_indicators': ['not found'], 'icon': '🔑', 'color': '#33A0FF'},
    'Product Hunt': {'url': 'https://www.producthunt.com/@{}', 'not_found_indicators': ['not found'], 'icon': '🏹', 'color': '#DA552F'},
    'Letterboxd': {'url': 'https://letterboxd.com/{}', 'not_found_indicators': ['not found'], 'icon': '🎬', 'color': '#202020'},
    'Last.fm': {'url': 'https://www.last.fm/user/{}', 'not_found_indicators': ['not found'], 'icon': '🎵', 'color': '#D51007'},
    'guns.lol': {'url': 'https://guns.lol/{}', 'not_found_indicators': ['not found'], 'icon': '🔫', 'color': '#FF4444'}
}


# ==================== USER LOOKUP (FIND EXISTING ACCOUNTS) ====================
class UsernameLookup:
    """Find existing accounts across platforms"""
    
    def __init__(self):
        self.platforms = PLATFORMS
        self.is_searching = False
        
    def check_platform(self, platform_name: str, platform_info: Dict, username: str) -> Tuple[str, bool, str]:
        """Check if username exists on a platform"""
        url = platform_info['url'].format(username)
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            # JSON API detection
            if platform_info.get('detection_type') == 'json_api':
                try:
                    api_url = platform_info['api_url'].format(username)
                    api_response = requests.get(api_url, headers=headers, timeout=10)
                    if api_response.status_code == 200:
                        return platform_name, True, url
                    return platform_name, False, url
                except:
                    return platform_name, False, url
            
            # Status code detection
            if platform_info.get('detection_type') == 'status_code':
                if response.status_code in [200, 301, 302]:
                    return platform_name, True, url
                return platform_name, False, url
            
            # Aggressive detection
            response_text = response.text.lower()
            not_found_indicators = platform_info.get('not_found_indicators', [])
            
            for indicator in not_found_indicators:
                if indicator.lower() in response_text:
                    return platform_name, False, url
            
            if response.status_code == 200:
                return platform_name, True, url
            elif response.status_code in [301, 302, 303, 307, 308]:
                return platform_name, True, url
            else:
                return platform_name, False, url
                
        except:
            return platform_name, False, url
    
    def search_all(self, username: str, progress_callback=None) -> Dict:
        """Search all platforms"""
        results = {}
        total = len(self.platforms)
        
        for idx, (name, info) in enumerate(self.platforms.items()):
            if not self.is_searching:
                break
            if progress_callback:
                progress_callback(name, idx + 1, total)
            
            name, exists, url = self.check_platform(name, info, username)
            results[name] = {'exists': exists, 'url': url}
            time.sleep(0.08)
        
        return results


# ==================== USERNAME AVAILABILITY CHECKER (CHECK IF AVAILABLE) ====================
class UsernameAvailability:
    """Check if username is available on platforms"""
    
    def __init__(self):
        self.platforms = PLATFORMS
        self.is_checking = False
        
    def check_platform(self, platform_name: str, platform_info: Dict, username: str) -> Tuple[str, bool, str]:
        """Check if username is available (not taken)"""
        url = platform_info['url'].format(username)
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            # JSON API detection
            if platform_info.get('detection_type') == 'json_api':
                try:
                    api_url = platform_info['api_url'].format(username)
                    api_response = requests.get(api_url, headers=headers, timeout=10)
                    if api_response.status_code == 200:
                        return platform_name, False, f"Taken (Account exists)"
                    return platform_name, True, f"Available"
                except:
                    return platform_name, False, f"Could not verify"
            
            # Status code detection
            if platform_info.get('detection_type') == 'status_code':
                if response.status_code in [200, 301, 302]:
                    return platform_name, False, f"Taken (Page exists)"
                return platform_name, True, f"Available"
            
            # Aggressive detection
            response_text = response.text.lower()
            not_found_indicators = platform_info.get('not_found_indicators', [])
            
            # Check for not found indicators
            for indicator in not_found_indicators:
                if indicator.lower() in response_text:
                    return platform_name, True, f"Available"
            
            # If we get a 200 and no not found indicators, account exists
            if response.status_code == 200:
                return platform_name, False, f"Taken"
            elif response.status_code == 404:
                return platform_name, True, f"Available"
            elif response.status_code in [301, 302, 303]:
                final_url = response.url.lower()
                if "login" not in final_url and "signup" not in final_url:
                    return platform_name, False, f"Taken (Redirects to profile)"
                return platform_name, True, f"Likely Available"
            else:
                return platform_name, False, f"Unknown (Status {response.status_code})"
                
        except:
            return platform_name, False, f"Could not verify"
    
    def check_all(self, username: str, progress_callback=None) -> Dict:
        """Check all platforms"""
        results = {}
        total = len(self.platforms)
        
        for idx, (name, info) in enumerate(self.platforms.items()):
            if not self.is_checking:
                break
            if progress_callback:
                progress_callback(name, idx + 1, total)
            
            name, available, message = self.check_platform(name, info, username)
            results[name] = {'available': available, 'message': message, 'url': info['url'].format(username)}
            time.sleep(0.08)
        
        return results


# ==================== DISCORD EXPORTER ====================
class DiscordExporter:
    def __init__(self):
        self.token_storage = TokenStorage()
        self.is_exporting = False
        
    def fetch_messages(self, headers, channel_id, limit=None, progress_callback=None):
        messages = []
        last_id = None
        total = 0
        
        while True:
            params = {'limit': 100}
            if last_id:
                params['before'] = last_id
            
            try:
                response = requests.get(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, params=params, timeout=30)
                if response.status_code != 200:
                    break
                batch = response.json()
                if not batch:
                    break
                messages.extend(batch)
                total += len(batch)
                last_id = batch[-1]['id']
                if limit:
                    if progress_callback:
                        progress_callback(total, limit, "Fetching...")
                    if total >= limit:
                        messages = messages[:limit]
                        break
                else:
                    if progress_callback:
                        progress_callback(total, total + 100, f"Fetched {total}")
                time.sleep(0.1)
            except:
                break
        return messages
    
    def export_messages(self, messages, channel_name, export_format, include_reactions=True, include_edits=True):
        """Export messages to files with options for reactions and edits"""
        exported = []
        export_dir = Path("discord_exports")
        export_dir.mkdir(exist_ok=True)
        
        processed = []
        for msg in messages:
            # Base message data
            msg_data = {
                'id': msg['id'],
                'author': msg['author']['username'],
                'content': msg['content'],
                'timestamp': datetime.fromisoformat(msg['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S'),
                'channel': channel_name
            }
            
            # Include reactions if enabled
            if include_reactions and msg.get('reactions'):
                reactions_list = []
                for r in msg.get('reactions', []):
                    emoji = r['emoji']
                    name = emoji.get('name') if emoji.get('name') else str(emoji.get('id', ''))
                    reactions_list.append({'emoji': name, 'count': r['count']})
                msg_data['reactions'] = reactions_list
            
            # Include edit info if enabled and message was edited
            if include_edits and msg.get('edited_timestamp'):
                msg_data['edited_timestamp'] = datetime.fromisoformat(msg['edited_timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
            
            processed.append(msg_data)
        
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = "".join(c for c in channel_name if c.isalnum() or c == ' ').rstrip()
        
        if export_format in ['json', 'all']:
            f = export_dir / f"{safe_name}_{ts}.json"
            with open(f, 'w', encoding='utf-8') as fp:
                json.dump(processed, fp, ensure_ascii=False, indent=2)
            exported.append(f)
        
        if export_format in ['csv', 'all']:
            f = export_dir / f"{safe_name}_{ts}.csv"
            with open(f, 'w', encoding='utf-8', newline='') as fp:
                fieldnames = ['id', 'author', 'content', 'timestamp', 'channel']
                if include_reactions:
                    fieldnames.append('reactions')
                if include_edits:
                    fieldnames.append('edited_timestamp')
                writer = csv.DictWriter(fp, fieldnames=fieldnames)
                writer.writeheader()
                for msg in processed:
                    row = {k: msg.get(k, '') for k in fieldnames}
                    if include_reactions and 'reactions' in msg:
                        row['reactions'] = json.dumps(msg['reactions'])
                    writer.writerow(row)
            exported.append(f)
        
        if export_format in ['txt', 'all']:
            f = export_dir / f"{safe_name}_{ts}.txt"
            with open(f, 'w', encoding='utf-8') as fp:
                fp.write(f"#{channel_name}\n{'='*40}\n")
                for msg in processed:
                    line = f"[{msg['timestamp']}] {msg['author']}: {msg['content']}"
                    if include_edits and msg.get('edited_timestamp'):
                        line += f" (edited at {msg['edited_timestamp']})"
                    fp.write(line + "\n")
                    if include_reactions and msg.get('reactions'):
                        reactions_str = "  Reactions: " + ", ".join([f"{r['emoji']} x{r['count']}" for r in msg['reactions']])
                        fp.write(reactions_str + "\n")
            exported.append(f)
        
        if export_format in ['html', 'all']:
            f = export_dir / f"{safe_name}_{ts}.html"
            with open(f, 'w', encoding='utf-8') as fp:
                fp.write(f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Discord Export - {channel_name}</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#1e1e1e;color:#e0e0e0;margin:0;padding:20px;}}
.container{{max-width:800px;margin:0 auto;background:#2d2d2d;border:1px solid #00ff00;border-radius:5px;}}
.header{{background:#2d2d2d;padding:15px;border-bottom:1px solid #00ff00;}}
.message{{padding:10px 15px;border-bottom:1px solid #3a3a3a;}}
.message:hover{{background:#3a3a3a;}}
.author{{font-weight:bold;color:#00ff00;margin-right:10px;}}
.timestamp{{font-size:11px;color:#888888;}}
.content{{margin-top:5px;white-space:pre-wrap;}}
.reactions{{font-size:11px;color:#888888;margin-top:5px;}}
.edited{{font-size:10px;color:#666666;margin-left:10px;}}
</style>
</head><body><div class="container"><div class="header"><h1 style="color:#00ff00;">#{channel_name}</h1>
<div>Total Messages: {len(processed)}</div><div>Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
<div style="font-size:11px;color:#888888;">discord.gg/fright</div></div>""")
                for msg in processed:
                    content = msg['content'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
                    fp.write(f"""<div class="message"><div><span class="author">{msg['author']}</span>
                    <span class="timestamp">{msg['timestamp']}</span>""")
                    if include_edits and msg.get('edited_timestamp'):
                        fp.write(f"""<span class="edited">(edited {msg['edited_timestamp']})</span>""")
                    fp.write(f"""</div><div class="content">{content if content else '<i>No text content</i>'}</div>""")
                    if include_reactions and msg.get('reactions'):
                        reactions_html = '<div class="reactions">Reactions: ' + ' '.join([f"{r['emoji']} x{r['count']}" for r in msg['reactions']]) + '</div>'
                        fp.write(reactions_html)
                    fp.write("</div>")
                fp.write("</div></body></html>")
            exported.append(f)
        return exported
    
    def export(self, token, channel_id, message_limit, export_format, include_reactions=True, include_edits=True, progress_callback=None, log_callback=None):
        self.is_exporting = True
        try:
            if progress_callback:
                progress_callback(0, 100, "Testing token...")
            headers = {'Authorization': token}
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
            if response.status_code != 200:
                if log_callback:
                    log_callback("Invalid token", 'error')
                return None
            user_info = response.json()
            if log_callback:
                log_callback(f"Logged in as: {user_info['username']}", 'success')
            
            if progress_callback:
                progress_callback(10, 100, "Getting channel...")
            response = requests.get(f'https://discord.com/api/v9/channels/{channel_id}', headers=headers)
            if response.status_code != 200:
                if log_callback:
                    log_callback("Channel not found", 'error')
                return None
            channel_info = response.json()
            channel_name = channel_info.get('name', str(channel_id))
            if log_callback:
                log_callback(f"Channel: #{channel_name}", 'success')
            
            if progress_callback:
                progress_callback(20, 100, "Fetching messages...")
            limit = int(message_limit) if message_limit and message_limit.strip() else None
            def fetch_progress(current, total, status):
                if progress_callback:
                    percent = 20 + (current / total) * 60 if total > 0 else 20
                    progress_callback(int(percent), 100, status)
            messages = self.fetch_messages(headers, int(channel_id), limit, fetch_progress)
            if not messages:
                if log_callback:
                    log_callback("No messages found", 'warning')
                return None
            if progress_callback:
                progress_callback(80, 100, "Exporting...")
            exported_files = self.export_messages(messages, channel_name, export_format, include_reactions, include_edits)
            if progress_callback:
                progress_callback(100, 100, "Complete!")
            if log_callback:
                log_callback(f"✓ Exported {len(exported_files)} file(s)", 'success')
                for f in exported_files[:3]:
                    log_callback(f"  📄 {f.name}", 'info')
            return exported_files
        except Exception as e:
            if log_callback:
                log_callback(f"Error: {str(e)}", 'error')
            return None
        finally:
            self.is_exporting = False


# ==================== MAIN GUI APPLICATION ====================
class CombinedApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        
        self.window = ctk.CTk()
        self.window.title("LARPSEC MAXX | discord.gg/fright")
        self.window.geometry("1100x850")
        self.window.minsize(1000, 750)
        
        self.accent_color = "#00ff00"
        
        self.username_lookup = UsernameLookup()
        self.username_availability = UsernameAvailability()
        self.email_analyzer = EmailAnalyzer()
        self.discord_exporter = DiscordExporter()
        
        self.setup_ui()
        
    def setup_ui(self):
        self.main_container = ctk.CTkFrame(self.window)
        self.main_container.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Header
        self.header_frame = ctk.CTkFrame(self.main_container)
        self.header_frame.pack(fill="x", padx=10, pady=(10, 15))
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="LARPSEC MAXX", font=ctk.CTkFont(size=32, weight="bold"), text_color=self.accent_color)
        self.title_label.pack(pady=(10, 5))
        
        self.subtitle_label = ctk.CTkLabel(self.header_frame, text="made by @crushable | property of 414", font=ctk.CTkFont(size=12))
        self.subtitle_label.pack()
        
        self.invite_label = ctk.CTkLabel(self.header_frame, text="discord.gg/fright", font=ctk.CTkFont(size=12, weight="bold"), text_color=self.accent_color)
        self.invite_label.pack(pady=(2, 0))
        
        # Tabview - Discord Exporter now in the middle
        self.tabview = ctk.CTkTabview(self.main_container)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.lookup_tab = self.tabview.add("🔍 User Lookup")
        self.availability_tab = self.tabview.add("✅ Availability Checker")
        self.exporter_tab = self.tabview.add("📥 Discord Exporter")  # Middle tab
        self.email_tab = self.tabview.add("📧 Email Lookup")
        self.iplookup_tab = self.tabview.add("🌐 IP Lookup")
        
        self.setup_lookup_tab()
        self.setup_availability_tab()
        self.setup_exporter_tab()
        self.setup_email_tab()
        self.setup_iplookup_tab()
        
        # Status bar
        self.status_frame = ctk.CTkFrame(self.main_container)
        self.status_frame.pack(fill="x", padx=10, pady=(10, 0))
        self.status_label = ctk.CTkLabel(self.status_frame, text="● Ready", font=ctk.CTkFont(size=11), anchor="w")
        self.status_label.pack(side="left", padx=5)
        self.timestamp_label = ctk.CTkLabel(self.status_frame, text="", font=ctk.CTkFont(size=11), anchor="e")
        self.timestamp_label.pack(side="right", padx=5)
    
    def setup_lookup_tab(self):
        """User Lookup - Find existing accounts"""
        search_frame = ctk.CTkFrame(self.lookup_tab)
        search_frame.pack(fill="x", padx=10, pady=10)
        
        self.lookup_entry = ctk.CTkEntry(search_frame, placeholder_text="Enter username to search across 50+ platforms...", font=ctk.CTkFont(size=14), height=45)
        self.lookup_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.lookup_entry.bind("<Return>", lambda e: self.start_lookup())
        
        self.lookup_button = ctk.CTkButton(search_frame, text="🔍 Search", command=self.start_lookup, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.lookup_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.lookup_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        self.lookup_progress_label = ctk.CTkLabel(progress_frame, text="Ready to search", font=ctk.CTkFont(size=12))
        self.lookup_progress_label.pack()
        self.lookup_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.lookup_progress_bar.pack(fill="x", pady=(5, 0))
        self.lookup_progress_bar.set(0)
        
        results_tabview = ctk.CTkTabview(self.lookup_tab)
        results_tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.found_tab = results_tabview.add("✅ Found Accounts")
        self.not_found_tab = results_tabview.add("❌ Not Found")
        
        self.found_scroll = ctk.CTkScrollableFrame(self.found_tab)
        self.found_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        self.not_found_scroll = ctk.CTkScrollableFrame(self.not_found_tab)
        self.not_found_scroll.pack(fill="both", expand=True, padx=10, pady=10)
    
    def setup_availability_tab(self):
        """Availability Checker - Check if username is available"""
        search_frame = ctk.CTkFrame(self.availability_tab)
        search_frame.pack(fill="x", padx=10, pady=10)
        
        self.avail_entry = ctk.CTkEntry(search_frame, placeholder_text="Enter username to check availability...", font=ctk.CTkFont(size=14), height=45)
        self.avail_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.avail_entry.bind("<Return>", lambda e: self.start_availability())
        
        self.avail_button = ctk.CTkButton(search_frame, text="✅ Check", command=self.start_availability, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.avail_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.availability_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        self.avail_progress_label = ctk.CTkLabel(progress_frame, text="Ready to check", font=ctk.CTkFont(size=12))
        self.avail_progress_label.pack()
        self.avail_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.avail_progress_bar.pack(fill="x", pady=(5, 0))
        self.avail_progress_bar.set(0)
        
        # Results treeview
        results_frame = ctk.CTkFrame(self.availability_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        tree_frame = tk.Frame(results_frame, bg="#1e1e1e")
        tree_frame.pack(fill="both", expand=True)
        
        self.avail_tree = ttk.Treeview(tree_frame, columns=('platform', 'status', 'details'), show='headings', height=20)
        self.avail_tree.heading('platform', text='Platform')
        self.avail_tree.heading('status', text='Status')
        self.avail_tree.heading('details', text='Details')
        self.avail_tree.column('platform', width=150)
        self.avail_tree.column('status', width=100, anchor='center')
        self.avail_tree.column('details', width=400)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.avail_tree.yview)
        self.avail_tree.configure(yscrollcommand=scrollbar.set)
        self.avail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.avail_tree.tag_configure('available', foreground='#4caf50')
        self.avail_tree.tag_configure('taken', foreground='#f44336')
        self.avail_tree.tag_configure('unknown', foreground='#ffaa44')
    
    def setup_exporter_tab(self):
        """Discord Exporter Tab - Now with reactions and edits options"""
        # Token section
        token_frame = ctk.CTkFrame(self.exporter_tab)
        token_frame.pack(fill="x", padx=10, pady=5)
        
        token_row = ctk.CTkFrame(token_frame)
        token_row.pack(fill="x", padx=5, pady=5)
        self.exporter_token_entry = ctk.CTkEntry(token_row, placeholder_text="Discord Token...", show="*", height=35)
        self.exporter_token_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(token_row, text="👁", width=40, command=self.toggle_token).pack(side="right", padx=2)
        ctk.CTkButton(token_row, text="?", width=40, command=self.show_token_help).pack(side="right")
        
        self.save_token_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(token_frame, text="Save token", variable=self.save_token_var).pack(anchor="w", padx=5, pady=2)
        
        # Channel section
        channel_frame = ctk.CTkFrame(self.exporter_tab)
        channel_frame.pack(fill="x", padx=10, pady=5)
        
        channel_row = ctk.CTkFrame(channel_frame)
        channel_row.pack(fill="x", padx=5, pady=5)
        self.channel_entry = ctk.CTkEntry(channel_row, placeholder_text="Channel ID...", height=35)
        self.channel_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(channel_row, text="?", width=40, command=self.show_channel_help).pack(side="right")
        
        limit_row = ctk.CTkFrame(channel_frame)
        limit_row.pack(fill="x", padx=5, pady=5)
        self.limit_entry = ctk.CTkEntry(limit_row, placeholder_text="Message limit (empty = all)", height=35)
        self.limit_entry.pack(side="left", fill="x", expand=True)
        
        # Export Format section
        format_frame = ctk.CTkFrame(self.exporter_tab)
        format_frame.pack(fill="x", padx=10, pady=5)
        format_label = ctk.CTkLabel(format_frame, text="Export Format:", font=ctk.CTkFont(size=12, weight="bold"))
        format_label.pack(anchor="w", padx=5, pady=(5, 0))
        
        format_row = ctk.CTkFrame(format_frame)
        format_row.pack(fill="x", padx=5, pady=5)
        self.export_format_var = tk.StringVar(value="all")
        for text, value in [("JSON", "json"), ("CSV", "csv"), ("HTML", "html"), ("TXT", "txt"), ("ALL", "all")]:
            ctk.CTkRadioButton(format_row, text=text, variable=self.export_format_var, value=value).pack(side="left", padx=5)
        
        # Options section - Reactions and Edits
        options_frame = ctk.CTkFrame(self.exporter_tab)
        options_frame.pack(fill="x", padx=10, pady=5)
        options_label = ctk.CTkLabel(options_frame, text="Export Options:", font=ctk.CTkFont(size=12, weight="bold"))
        options_label.pack(anchor="w", padx=5, pady=(5, 0))
        
        options_row = ctk.CTkFrame(options_frame)
        options_row.pack(fill="x", padx=5, pady=5)
        
        self.include_reactions_var = tk.BooleanVar(value=True)
        self.include_reactions_check = ctk.CTkCheckBox(options_row, text="Include Reactions", variable=self.include_reactions_var)
        self.include_reactions_check.pack(side="left", padx=10)
        
        self.include_edits_var = tk.BooleanVar(value=True)
        self.include_edits_check = ctk.CTkCheckBox(options_row, text="Include Edit Timestamps", variable=self.include_edits_var)
        self.include_edits_check.pack(side="left", padx=10)
        
        # Progress section
        progress_frame = ctk.CTkFrame(self.exporter_tab)
        progress_frame.pack(fill="x", padx=10, pady=5)
        self.export_progress_label = ctk.CTkLabel(progress_frame, text="Ready", font=ctk.CTkFont(size=12))
        self.export_progress_label.pack()
        self.export_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.export_progress_bar.pack(fill="x", pady=(5, 0))
        self.export_progress_bar.set(0)
        self.export_status_label = ctk.CTkLabel(progress_frame, text="", font=ctk.CTkFont(size=11), text_color="#888888")
        self.export_status_label.pack()
        
        # Log section
        log_frame = ctk.CTkFrame(self.exporter_tab)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        log_label = ctk.CTkLabel(log_frame, text="Log:", font=ctk.CTkFont(size=12, weight="bold"))
        log_label.pack(anchor="w", padx=5, pady=(5, 0))
        self.export_log_text = ctk.CTkTextbox(log_frame, font=ctk.CTkFont(size=11), height=150)
        self.export_log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Buttons
        button_frame = ctk.CTkFrame(self.exporter_tab)
        button_frame.pack(fill="x", padx=10, pady=10)
        self.export_button = ctk.CTkButton(button_frame, text="▶ START EXPORT", command=self.start_export, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        self.export_button.pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(button_frame, text="🗑 CLEAR", command=self.clear_export_log, height=40).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="🔑 CLEAR TOKEN", command=self.clear_token, height=40).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="📁 OPEN", command=self.open_export_folder, height=40).pack(side="left", padx=5)
        
        self.load_saved_token()
    
    def setup_email_tab(self):
        """Email Lookup Tab"""
        input_frame = ctk.CTkFrame(self.email_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.email_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter email address to analyze...", font=ctk.CTkFont(size=14), height=45)
        self.email_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.email_entry.bind("<Return>", lambda e: self.start_email_lookup())
        
        self.email_button = ctk.CTkButton(input_frame, text="📧 Analyze", command=self.start_email_lookup, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.email_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.email_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        self.email_progress_label = ctk.CTkLabel(progress_frame, text="Ready to analyze", font=ctk.CTkFont(size=12))
        self.email_progress_label.pack()
        self.email_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.email_progress_bar.pack(fill="x", pady=(5, 0))
        self.email_progress_bar.set(0)
        
        results_frame = ctk.CTkFrame(self.email_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.email_results_text = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=12))
        self.email_results_text.pack(fill="both", expand=True)
        
        button_frame = ctk.CTkFrame(self.email_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(button_frame, text="📋 Copy", command=self.copy_email_results, height=35).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="🗑 Clear", command=self.clear_email_results, height=35).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="💾 Save", command=self.save_email_results, height=35).pack(side="left", padx=5)
    
    def setup_iplookup_tab(self):
        """IP Lookup Tab"""
        input_frame = ctk.CTkFrame(self.iplookup_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.ip_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter IP address (e.g., 8.8.8.8)...", font=ctk.CTkFont(size=14), height=45)
        self.ip_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.ip_entry.bind("<Return>", lambda e: self.start_ip_lookup())
        
        self.ip_button = ctk.CTkButton(input_frame, text="🌐 Lookup", command=self.start_ip_lookup, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.ip_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.iplookup_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        self.ip_progress_label = ctk.CTkLabel(progress_frame, text="Ready to lookup", font=ctk.CTkFont(size=12))
        self.ip_progress_label.pack()
        self.ip_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.ip_progress_bar.pack(fill="x", pady=(5, 0))
        self.ip_progress_bar.set(0)
        
        results_frame = ctk.CTkFrame(self.iplookup_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.ip_results_text = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=12))
        self.ip_results_text.pack(fill="both", expand=True)
        
        button_frame = ctk.CTkFrame(self.iplookup_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(button_frame, text="📋 Copy", command=self.copy_ip_results, height=35).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="🗑 Clear", command=self.clear_ip_results, height=35).pack(side="left", padx=5)
    
    # ==================== Lookup Methods ====================
    def start_lookup(self):
        username = self.lookup_entry.get().strip()
        if not username:
            self.status_label.configure(text="⚠ Please enter a username", text_color="orange")
            return
        
        for widget in self.found_scroll.winfo_children():
            widget.destroy()
        for widget in self.not_found_scroll.winfo_children():
            widget.destroy()
        
        self.username_lookup.is_searching = True
        self.lookup_button.configure(text="⏹ Stop", command=self.stop_lookup)
        self.lookup_entry.configure(state="disabled")
        self.lookup_progress_bar.set(0)
        self.status_label.configure(text="🔍 Searching...", text_color="green")
        
        thread = threading.Thread(target=self.perform_lookup, args=(username,))
        thread.daemon = True
        thread.start()
    
    def stop_lookup(self):
        self.username_lookup.is_searching = False
        self.status_label.configure(text="⏹ Search stopped", text_color="orange")
    
    def perform_lookup(self, username):
        try:
            def progress(name, current, total):
                self.window.after(0, self.update_lookup_progress, name, current, total)
            results = self.username_lookup.search_all(username, progress)
            if self.username_lookup.is_searching:
                self.window.after(0, self.display_lookup_results, results)
        except Exception as e:
            self.window.after(0, lambda: self.status_label.configure(text=f"⚠ Error: {e}", text_color="red"))
        finally:
            self.window.after(0, self.lookup_complete)
    
    def update_lookup_progress(self, name, current, total):
        progress = current / total
        self.lookup_progress_bar.set(progress)
        self.lookup_progress_label.configure(text=f"Searching {name}... ({current}/{total})")
    
    def display_lookup_results(self, results):
        found = [(p, d['url']) for p, d in results.items() if d['exists']]
        not_found = [p for p, d in results.items() if not d['exists']]
        
        if found:
            for platform, url in found:
                info = PLATFORMS.get(platform, {})
                frame = ctk.CTkFrame(self.found_scroll)
                frame.pack(fill="x", padx=10, pady=2)
                ctk.CTkLabel(frame, text=f"{info.get('icon', '')} {platform}", width=150, anchor="w").pack(side="left", padx=10)
                btn = ctk.CTkButton(frame, text=url, fg_color="transparent", hover_color=info.get('color', '#2b2b2b'), text_color="#2ecc71", anchor="w", command=lambda u=url: webbrowser.open(u))
                btn.pack(side="left", fill="x", expand=True, padx=10)
        else:
            ctk.CTkLabel(self.found_scroll, text="No accounts found", font=ctk.CTkFont(size=14)).pack(pady=20)
        
        if not_found:
            for platform in not_found:
                info = PLATFORMS.get(platform, {})
                frame = ctk.CTkFrame(self.not_found_scroll)
                frame.pack(fill="x", padx=10, pady=2)
                ctk.CTkLabel(frame, text=f"{info.get('icon', '')} {platform}", anchor="w").pack(side="left", padx=10)
        else:
            ctk.CTkLabel(self.not_found_scroll, text="All accounts found! 🎉", font=ctk.CTkFont(size=14)).pack(pady=20)
        
        found_count = len(found)
        total = len(results)
        self.status_label.configure(text=f"✓ Found {found_count}/{total} accounts", text_color="green")
        self.timestamp_label.configure(text=datetime.now().strftime("%H:%M:%S"))
    
    def lookup_complete(self):
        self.username_lookup.is_searching = False
        self.lookup_button.configure(text="🔍 Search", command=self.start_lookup)
        self.lookup_entry.configure(state="normal")
        self.lookup_progress_label.configure(text="Search complete")
    
    # ==================== Availability Methods ====================
    def start_availability(self):
        username = self.avail_entry.get().strip()
        if not username:
            self.status_label.configure(text="⚠ Please enter a username", text_color="orange")
            return
        
        for item in self.avail_tree.get_children():
            self.avail_tree.delete(item)
        
        self.username_availability.is_checking = True
        self.avail_button.configure(text="⏹ Stop", command=self.stop_availability)
        self.avail_entry.configure(state="disabled")
        self.avail_progress_bar.set(0)
        self.status_label.configure(text="🔍 Checking availability...", text_color="green")
        
        thread = threading.Thread(target=self.perform_availability, args=(username,))
        thread.daemon = True
        thread.start()
    
    def stop_availability(self):
        self.username_availability.is_checking = False
        self.status_label.configure(text="⏹ Check stopped", text_color="orange")
    
    def perform_availability(self, username):
        try:
            def progress(name, current, total):
                self.window.after(0, self.update_avail_progress, name, current, total)
            results = self.username_availability.check_all(username, progress)
            if self.username_availability.is_checking:
                self.window.after(0, self.display_availability_results, results)
        except Exception as e:
            self.window.after(0, lambda: self.status_label.configure(text=f"⚠ Error: {e}", text_color="red"))
        finally:
            self.window.after(0, self.availability_complete)
    
    def update_avail_progress(self, name, current, total):
        progress = current / total
        self.avail_progress_bar.set(progress)
        self.avail_progress_label.configure(text=f"Checking {name}... ({current}/{total})")
    
    def display_availability_results(self, results):
        for platform, data in results.items():
            info = PLATFORMS.get(platform, {})
            icon = info.get('icon', '')
            status_text = "✓ AVAILABLE" if data['available'] else "✗ TAKEN"
            tag = 'available' if data['available'] else 'taken'
            self.avail_tree.insert('', tk.END, values=(f"{icon} {platform}", status_text, data['message']), tags=(tag,))
        
        available = sum(1 for d in results.values() if d['available'])
        total = len(results)
        self.status_label.configure(text=f"✓ {available}/{total} usernames available", text_color="green")
        self.timestamp_label.configure(text=datetime.now().strftime("%H:%M:%S"))
    
    def availability_complete(self):
        self.username_availability.is_checking = False
        self.avail_button.configure(text="✅ Check", command=self.start_availability)
        self.avail_entry.configure(state="normal")
        self.avail_progress_label.configure(text="Check complete")
    
    # ==================== Email Methods ====================
    def start_email_lookup(self):
        email = self.email_entry.get().strip()
        if not email:
            self.status_label.configure(text="⚠ Please enter an email", text_color="orange")
            return
        
        self.email_button.configure(text="⏹ Analyzing...", state="disabled")
        self.email_entry.configure(state="disabled")
        self.email_progress_bar.set(0)
        self.email_results_text.delete("1.0", "end")
        self.status_label.configure(text=f"🔍 Analyzing: {email}", text_color="green")
        
        thread = threading.Thread(target=self.perform_email_lookup, args=(email,))
        thread.daemon = True
        thread.start()
    
    def perform_email_lookup(self, email):
        try:
            self.window.after(0, self.update_email_progress, 20)
            results = self.email_analyzer.analyze_email(email)
            self.window.after(0, self.display_email_results, results)
            self.window.after(0, self.status_label.configure, {"text": f"✓ Analysis complete", "text_color": "green"})
        except Exception as e:
            self.window.after(0, lambda: self.status_label.configure(text=f"⚠ Error: {e}", text_color="red"))
        finally:
            self.window.after(0, self.email_complete)
    
    def update_email_progress(self, percent):
        self.email_progress_bar.set(percent / 100)
        self.email_progress_label.configure(text="Analyzing...")
    
    def display_email_results(self, results):
        self.email_results_text.tag_config("header", foreground="#00ff00")
        self.email_results_text.tag_config("section", foreground="#00ff00")
        
        header = f"{'='*70}\nEMAIL ANALYSIS REPORT\nEmail: {results['email']}\n{'='*70}\n\n"
        self.email_results_text.insert("end", header, "header")
        
        v = results['validation']
        self.email_results_text.insert("end", "📧 Validation\n", "section")
        self.email_results_text.insert("end", f"  Format: {'✅ Valid' if v['format_valid'] else '❌ Invalid'}\n")
        self.email_results_text.insert("end", f"  MX Records: {'✅ Yes' if v['mx_records_exist'] else '❌ No'}\n")
        if v.get('mx_records'):
            self.email_results_text.insert("end", f"  Mail Servers: {', '.join(v['mx_records'][:2])}\n")
        self.email_results_text.insert("end", f"  Disposable: {'⚠️ Yes' if v['disposable'] else 'No'}\n")
        self.email_results_text.insert("end", f"  Free Provider: {'⚠️ Yes' if v['free_provider'] else 'No'}\n\n")
        
        d = results['domain_analysis']
        self.email_results_text.insert("end", "🌐 Domain\n", "section")
        self.email_results_text.insert("end", f"  Domain: {d['domain']}\n")
        if d.get('age_days'):
            self.email_results_text.insert("end", f"  Age: {d['age_days']} days\n")
        if d.get('has_website'):
            self.email_results_text.insert("end", f"  Website: Yes (Status {d['website_status']})\n")
        
        s = results['security']
        self.email_results_text.insert("end", "\n🔒 Security\n", "section")
        self.email_results_text.insert("end", f"  SPF: {'✅' if s['spf_record'] else '❌'}\n")
        self.email_results_text.insert("end", f"  DMARC: {'✅' if s['dmarc_record'] else '❌'}\n\n")
        
        b = results['data_breaches']
        self.email_results_text.insert("end", "⚠️ Breaches\n", "section")
        if b.get('breached'):
            self.email_results_text.insert("end", f"  ⚠️ Found in {b['breach_count']} breaches!\n")
            for breach in b['breaches'][:3]:
                self.email_results_text.insert("end", f"    • {breach['name']} ({breach['date']})\n")
        else:
            self.email_results_text.insert("end", "  ✅ No known breaches\n")
        
        g = results['gravatar']
        self.email_results_text.insert("end", "\n👤 Gravatar\n", "section")
        if g['has_gravatar']:
            self.email_results_text.insert("end", f"  ✅ Profile found\n")
            if g.get('name'):
                self.email_results_text.insert("end", f"  Name: {g['name']}\n")
        else:
            self.email_results_text.insert("end", "  ❌ No profile\n")
        
        footer = f"\n{'='*70}\nAnalysis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        self.email_results_text.insert("end", footer)
        self.email_results_text.see("1.0")
    
    def email_complete(self):
        self.email_button.configure(text="📧 Analyze", command=self.start_email_lookup, state="normal")
        self.email_entry.configure(state="normal")
        self.email_progress_label.configure(text="Analysis complete")
        self.email_progress_bar.set(1.0)
        self.window.after(2000, lambda: self.email_progress_bar.set(0))
    
    def copy_email_results(self):
        text = self.email_results_text.get("1.0", "end-1c")
        if text.strip():
            self.window.clipboard_clear()
            self.window.clipboard_append(text)
            self.status_label.configure(text="✓ Copied", text_color="green")
            self.window.after(2000, lambda: self.status_label.configure(text="● Ready", text_color="white"))
    
    def clear_email_results(self):
        self.email_results_text.delete("1.0", "end")
        self.status_label.configure(text="● Cleared", text_color="white")
    
    def save_email_results(self):
        text = self.email_results_text.get("1.0", "end-1c")
        if text.strip():
            filename = f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(text)
            self.status_label.configure(text=f"✓ Saved to {filename}", text_color="green")
            self.window.after(3000, lambda: self.status_label.configure(text="● Ready", text_color="white"))
    
    # ==================== IP Methods ====================
    def start_ip_lookup(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            self.status_label.configure(text="⚠ Enter IP address", text_color="orange")
            return
        
        self.ip_button.configure(text="⏹ Looking up...", state="disabled")
        self.ip_entry.configure(state="disabled")
        self.ip_progress_bar.set(0)
        self.ip_results_text.delete("1.0", "end")
        self.status_label.configure(text=f"🔍 Looking up: {ip}", text_color="green")
        
        thread = threading.Thread(target=self.perform_ip_lookup, args=(ip,))
        thread.daemon = True
        thread.start()
    
    def perform_ip_lookup(self, ip):
        try:
            self.window.after(0, lambda: self.ip_progress_label.configure(text="Fetching..."))
            gatherer = IPInformationGatherer(ip)
            results = gatherer.get_all_info()
            self.window.after(0, self.display_ip_results, results)
            self.window.after(0, self.status_label.configure, {"text": f"✓ Lookup complete", "text_color": "green"})
        except Exception as e:
            self.window.after(0, lambda: self.status_label.configure(text=f"⚠ Error: {e}", text_color="red"))
        finally:
            self.window.after(0, self.ip_complete)
    
    def display_ip_results(self, results):
        self.ip_results_text.tag_config("header", foreground="#00ff00")
        if 'error' in results:
            self.ip_results_text.insert("1.0", f"Error: {results['error']}")
            return
        
        header = f"{'='*70}\nIP REPORT: {results['ip_address']}\n{'='*70}\n\n"
        self.ip_results_text.insert("end", header, "header")
        self.ip_results_text.insert("end", f"IP Type: {results['ip_type']}\n")
        self.ip_results_text.insert("end", f"Hostname: {results['hostname']}\n\n")
        
        api = results['ip_api']
        if 'error' not in api:
            self.ip_results_text.insert("end", "Geolocation:\n")
            self.ip_results_text.insert("end", f"  Country: {api.get('country', 'Unknown')}\n")
            self.ip_results_text.insert("end", f"  Region: {api.get('region', 'Unknown')}\n")
            self.ip_results_text.insert("end", f"  City: {api.get('city', 'Unknown')}\n")
            self.ip_results_text.insert("end", f"  ISP: {api.get('isp', 'Unknown')}\n")
            self.ip_results_text.insert("end", f"  Organization: {api.get('organization', 'Unknown')}\n")
        
        footer = f"\n{'='*70}\nLookup: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        self.ip_results_text.insert("end", footer)
    
    def ip_complete(self):
        self.ip_button.configure(text="🌐 Lookup", command=self.start_ip_lookup, state="normal")
        self.ip_entry.configure(state="normal")
        self.ip_progress_label.configure(text="Complete")
        self.ip_progress_bar.set(1.0)
        self.window.after(2000, lambda: self.ip_progress_bar.set(0))
    
    def copy_ip_results(self):
        text = self.ip_results_text.get("1.0", "end-1c")
        if text.strip():
            self.window.clipboard_clear()
            self.window.clipboard_append(text)
            self.status_label.configure(text="✓ Copied", text_color="green")
            self.window.after(2000, lambda: self.status_label.configure(text="● Ready", text_color="white"))
    
    def clear_ip_results(self):
        self.ip_results_text.delete("1.0", "end")
        self.status_label.configure(text="● Cleared", text_color="white")
    
    # ==================== Discord Methods ====================
    def toggle_token(self):
        if self.exporter_token_entry.cget('show') == '*':
            self.exporter_token_entry.configure(show='')
        else:
            self.exporter_token_entry.configure(show='*')
    
    def show_token_help(self):
        messagebox.showinfo("Get Token", "1. Open Discord in browser (F12)\n2. Network tab → Refresh\n3. Click any request\n4. Copy 'authorization' header")
    
    def show_channel_help(self):
        messagebox.showinfo("Get Channel ID", "Enable Developer Mode:\nSettings → Advanced → Developer Mode\nRight-click channel → Copy ID")
    
    def load_saved_token(self):
        token = self.discord_exporter.token_storage.load_token()
        if token:
            self.exporter_token_entry.insert(0, token)
            self.log_export("Loaded saved token")
    
    def clear_token(self):
        if messagebox.askyesno("Confirm", "Clear saved token?"):
            self.discord_exporter.token_storage.clear_token()
            self.exporter_token_entry.delete(0, tk.END)
            self.log_export("Token cleared")
    
    def open_export_folder(self):
        export_dir = Path("discord_exports")
        if export_dir.exists():
            if sys.platform == 'win32':
                os.startfile(export_dir)
            else:
                os.system(f'open "{export_dir}"' if sys.platform == 'darwin' else f'xdg-open "{export_dir}"')
        else:
            messagebox.showinfo("No Exports", "Export some chats first!")
    
    def log_export(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.export_log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.export_log_text.see(tk.END)
    
    def clear_export_log(self):
        self.export_log_text.delete("1.0", tk.END)
    
    def update_export_progress(self, current, total, status):
        if total > 0:
            percent = (current / total) * 100
            self.export_progress_bar.set(percent / 100)
            self.export_progress_label.configure(text=f"{current}/{total} ({percent:.0f}%)")
            if status:
                self.export_status_label.configure(text=status)
        if current == total:
            self.export_status_label.configure(text="✓ Complete!")
    
    def perform_export(self):
        token = self.exporter_token_entry.get().strip()
        channel = self.channel_entry.get().strip()
        limit = self.limit_entry.get().strip()
        fmt = self.export_format_var.get()
        include_reactions = self.include_reactions_var.get()
        include_edits = self.include_edits_var.get()
        
        def progress_cb(current, total, status):
            self.window.after(0, self.update_export_progress, current, total, status)
        def log_cb(msg, tag):
            self.window.after(0, self.log_export, msg)
        
        if self.save_token_var.get() and token:
            self.discord_exporter.token_storage.save_token(token)
        
        self.discord_exporter.export(token, channel, limit, fmt, include_reactions, include_edits, progress_cb, log_cb)
        self.window.after(0, self.export_complete)
    
    def export_complete(self):
        self.export_button.configure(text="▶ START EXPORT", command=self.start_export, state="normal")
        self.export_progress_label.configure(text="Ready")
        self.export_status_label.configure(text="")
    
    def start_export(self):
        token = self.exporter_token_entry.get().strip()
        channel = self.channel_entry.get().strip()
        
        if not token:
            messagebox.showerror("Error", "Enter Discord token")
            return
        if not channel:
            messagebox.showerror("Error", "Enter channel ID")
            return
        
        self.export_button.configure(text="⏹ Exporting...", state="disabled")
        self.export_progress_bar.set(0)
        self.export_progress_label.configure(text="Starting...")
        self.export_status_label.configure(text="")
        
        thread = threading.Thread(target=self.perform_export)
        thread.daemon = True
        thread.start()
    
    def run(self):
        self.window.mainloop()


def main():
    try:
        import dns.resolver, whois
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython", "python-whois", "email-validator"])
    
    app = CombinedApp()
    app.run()


if __name__ == "__main__":
    main()