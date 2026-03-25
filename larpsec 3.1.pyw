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
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import hashlib
import whois
import random
import string
import qrcode
from PIL import Image, ImageTk
import io
import urllib.parse
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
            
            if 'remarks' in data:
                remarks = []
                for remark in data['remarks']:
                    if 'description' in remark:
                        remarks.extend(remark['description'])
                if remarks:
                    rdap_dict['remarks'] = ' '.join(remarks)
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


# ==================== EMAIL/PHONE ANALYZER ====================
class ContactInfoAnalyzer:
    def __init__(self):
        self.results = {}
    
    def identify_input_type(self, input_str):
        input_str = input_str.strip()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, input_str):
            return 'email'
        phone_pattern = r'^[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{3,4}[-\s\.]?[0-9]{3,4}$'
        if re.match(phone_pattern, input_str):
            return 'phone'
        return 'unknown'
    
    def analyze_email(self, email_address):
        results = {
            'email': email_address,
            'validation': {},
            'domain_analysis': {},
            'security': {},
            'social_media': {},
            'data_breaches': {},
            'gravatar': {}
        }
        
        results['validation'] = self._validate_email(email_address)
        domain = email_address.split('@')[1]
        results['domain_analysis'] = self._analyze_domain(domain)
        results['security'] = self._check_email_security(email_address)
        results['data_breaches'] = self._check_breaches(email_address)
        results['gravatar'] = self._check_gravatar(email_address)
        results['social_media'] = self._check_social_media(email_address)
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
            validation['mx_records_exist'] = False
        
        disposable_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com']
        validation['disposable'] = domain in disposable_domains
        
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'protonmail.com', 'mail.com']
        validation['free_provider'] = domain in free_providers
        
        return validation
    
    def _analyze_domain(self, domain):
        analysis = {'domain': domain, 'whois_info': {}, 'age_days': None, 'has_website': False, 'website_status': None, 'ip_addresses': []}
        try:
            w = whois.whois(domain)
            analysis['whois_info'] = {'registrar': w.registrar, 'creation_date': str(w.creation_date) if w.creation_date else None, 'expiration_date': str(w.expiration_date) if w.expiration_date else None, 'name_servers': w.name_servers, 'organization': w.org}
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
            analysis['has_website'] = False
        return analysis
    
    def _check_email_security(self, email_address):
        security = {'spf_record': False, 'dkim_record': False, 'dmarc_record': False, 'spf_details': None, 'dkim_details': None, 'dmarc_details': None}
        domain = email_address.split('@')[1]
        try:
            spf = dns.resolver.resolve(domain, 'TXT')
            for record in spf:
                if 'v=spf1' in str(record):
                    security['spf_record'] = True
                    security['spf_details'] = str(record)
                    break
        except:
            pass
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc:
                if 'v=DMARC1' in str(record):
                    security['dmarc_record'] = True
                    security['dmarc_details'] = str(record)
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
                breaches['breaches'] = [{'name': breach['Name'], 'date': breach['BreachDate'], 'description': breach['Description'][:200]} for breach in data[:5]]
            elif response.status_code == 404:
                breaches['breached'] = False
        except:
            breaches['error'] = "Could not check breaches"
        return breaches
    
    def _check_gravatar(self, email_address):
        gravatar = {'has_gravatar': False, 'profile_url': None, 'avatar_url': None, 'name': None, 'location': None}
        email_hash = hashlib.md5(email_address.lower().encode()).hexdigest()
        gravatar['avatar_url'] = f"https://www.gravatar.com/avatar/{email_hash}"
        try:
            response = requests.get(f"https://www.gravatar.com/{email_hash}.json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'entry' in data and data['entry']:
                    gravatar['has_gravatar'] = True
                    entry = data['entry'][0]
                    gravatar['name'] = entry.get('displayName', '')
                    gravatar['profile_url'] = entry.get('profileUrl', '')
        except:
            pass
        return gravatar
    
    def _check_social_media(self, email_address):
        social_media = {'twitter': None, 'linkedin': None, 'github': None, 'facebook': None}
        username = email_address.split('@')[0]
        try:
            response = requests.get(f"https://api.github.com/users/{username}", timeout=5)
            if response.status_code == 200:
                social_media['github'] = f"https://github.com/{username}"
        except:
            pass
        try:
            response = requests.get(f"https://www.facebook.com/{username}", timeout=5)
            if response.status_code == 200:
                social_media['facebook'] = f"https://facebook.com/{username}"
        except:
            pass
        return social_media
    
    def _get_email_intelligence(self, email_address):
        intelligence = {'domain_reputation': 'Unknown', 'common_variations': [], 'possible_names': []}
        username = email_address.split('@')[0]
        domain = email_address.split('@')[1]
        possible_name = re.sub(r'[._-]', ' ', username)
        intelligence['possible_names'] = [possible_name]
        variations = [f"{username}.work@{domain}", f"{username}.official@{domain}", f"{username}1@{domain}"]
        intelligence['common_variations'] = variations
        return intelligence
    
    def analyze_phone(self, phone_number, country_code='US'):
        results = {'phone_number': phone_number, 'parsed_info': {}, 'carrier_info': {}, 'location_info': {}, 'timezone_info': [], 'validation': {}, 'reputation': {}, 'additional_info': {}}
        try:
            parsed_number = phonenumbers.parse(phone_number, country_code)
            results['parsed_info'] = {'country_code': parsed_number.country_code, 'national_number': parsed_number.national_number, 'extension': parsed_number.extension, 'is_possible_number': phonenumbers.is_possible_number(parsed_number), 'is_valid_number': phonenumbers.is_valid_number(parsed_number)}
            carrier_name = carrier.name_for_number(parsed_number, "en")
            results['carrier_info'] = {'name': carrier_name if carrier_name else 'Unknown', 'is_mobile': phonenumbers.number_type(parsed_number) in [1, 2, 3], 'number_type': self._get_number_type(parsed_number)}
            location = geocoder.description_for_number(parsed_number, "en")
            results['location_info'] = {'description': location if location else 'Unknown', 'country': geocoder.country_name_for_number(parsed_number, "en")}
            timezones = timezone.time_zones_for_number(parsed_number)
            results['timezone_info'] = list(timezones) if timezones else []
            results['validation'] = {'is_possible': phonenumbers.is_possible_number(parsed_number), 'is_valid': phonenumbers.is_valid_number(parsed_number), 'is_emergency_number': phonenumbers.is_emergency_number(parsed_number)}
        except phonenumbers.NumberParseException as e:
            results['error'] = f"Could not parse phone number: {e}"
            return results
        results['additional_info'] = self._get_phone_intelligence(parsed_number)
        self.results = results
        return results
    
    def _get_number_type(self, parsed_number):
        number_type = phonenumbers.number_type(parsed_number)
        types = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST", 6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER", 9: "UAN", 10: "VOICEMAIL", 11: "UNKNOWN"}
        return types.get(number_type, "UNKNOWN")
    
    def _get_phone_intelligence(self, parsed_number):
        intelligence = {'possible_spoofing': False, 'common_issues': [], 'suggestions': []}
        national_number = str(parsed_number.national_number)
        if len(set(national_number)) <= 3:
            intelligence['possible_spoofing'] = True
            intelligence['common_issues'].append("Number has repeated digits pattern")
        if parsed_number.country_code == 1 and national_number.startswith(('800', '888', '877', '866', '855')):
            intelligence['common_issues'].append("This is a toll-free number")
        return intelligence


# ==================== REVERSE IMAGE SEARCH ====================
class ReverseImageSearch:
    def __init__(self):
        self.search_engines = {
            'Google Images': 'https://www.google.com/searchbyimage?image_url={}',
            'Bing Visual Search': 'https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlInfo&q=imgurl:{}',
            'Yandex Images': 'https://yandex.com/images/search?rpt=imageview&url={}',
            'Tineye': 'https://tineye.com/search?url={}'
        }
    
    def search_by_url(self, image_url):
        results = {}
        for engine_name, url_template in self.search_engines.items():
            search_url = url_template.format(urllib.parse.quote(image_url))
            results[engine_name] = search_url
        return results
    
    def search_by_file(self, file_path):
        try:
            files = {'image': open(file_path, 'rb')}
            response = requests.post('https://www.google.com/searchbyimage/upload', files=files, timeout=30)
            if response.url:
                return {'Google Images': response.url}
            return {'error': 'Could not upload image'}
        except Exception as e:
            return {'error': f'Upload failed: {str(e)}'}


# ==================== URL SCANNER ====================
class URLScanner:
    def __init__(self):
        self.virus_total_key = None
    
    def set_virustotal_key(self, api_key):
        self.virus_total_key = api_key
    
    def scan_url(self, url):
        results = {
            'url': url,
            'safety_checks': {},
            'reputation': {},
            'technical_details': {}
        }
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urllib.parse.urlparse(url)
        results['technical_details'] = {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query
        }
        
        domain = parsed.netloc
        results['safety_checks']['domain'] = domain
        
        suspicious_patterns = ['login', 'secure', 'verify', 'account', 'update', 'confirm', 'signin', 'bank', 'paypal']
        domain_lower = domain.lower()
        results['safety_checks']['suspicious_keywords'] = any(pattern in domain_lower for pattern in suspicious_patterns)
        
        results['safety_checks']['url_length'] = len(url)
        results['safety_checks']['is_long_url'] = len(url) > 100
        
        try:
            ipaddress.ip_address(domain.split(':')[0])
            results['safety_checks']['uses_ip_address'] = True
        except:
            results['safety_checks']['uses_ip_address'] = False
        
        subdomain_count = domain.count('.')
        results['safety_checks']['subdomain_count'] = subdomain_count
        results['safety_checks']['excessive_subdomains'] = subdomain_count > 4
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            results['technical_details']['status_code'] = response.status_code
            results['technical_details']['final_url'] = response.url
            results['technical_details']['redirect_count'] = len(response.history)
            
            if response.status_code == 200:
                results['safety_checks']['is_accessible'] = True
            else:
                results['safety_checks']['is_accessible'] = False
                results['safety_checks']['status'] = f"HTTP {response.status_code}"
        except Exception as e:
            results['safety_checks']['is_accessible'] = False
            results['safety_checks']['error'] = str(e)
        
        results['reputation']['risk_level'] = self._assess_risk(results['safety_checks'])
        
        return results
    
    def _assess_risk(self, checks):
        risk_score = 0
        if checks.get('suspicious_keywords'):
            risk_score += 2
        if checks.get('is_long_url'):
            risk_score += 1
        if checks.get('uses_ip_address'):
            risk_score += 3
        if checks.get('excessive_subdomains'):
            risk_score += 1
        if not checks.get('is_accessible'):
            risk_score += 1
        
        if risk_score >= 5:
            return "HIGH RISK"
        elif risk_score >= 3:
            return "MEDIUM RISK"
        elif risk_score >= 1:
            return "LOW RISK"
        else:
            return "SAFE"


# ==================== PASSWORD GENERATOR ====================
class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def generate_password(self, length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
        charset = ""
        if use_lower:
            charset += self.lowercase
        if use_upper:
            charset += self.uppercase
        if use_digits:
            charset += self.digits
        if use_symbols:
            charset += self.symbols
        
        if not charset:
            return "Select at least one character type"
        
        password = ''.join(random.choice(charset) for _ in range(length))
        return password
    
    def check_strength(self, password):
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 1
            feedback.append("✓ Good length (12+ characters)")
        elif len(password) >= 8:
            feedback.append("⚠️ Consider using 12+ characters")
        else:
            feedback.append("❌ Password is too short")
        
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("❌ Missing lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("❌ Missing uppercase letters")
        
        if re.search(r'\d', password):
            score += 1
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("❌ Missing numbers")
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?]', password):
            score += 1
            feedback.append("✓ Contains symbols")
        else:
            feedback.append("❌ Missing symbols")
        
        if score >= 5:
            strength = "VERY STRONG"
        elif score >= 4:
            strength = "STRONG"
        elif score >= 3:
            strength = "MEDIUM"
        elif score >= 2:
            strength = "WEAK"
        else:
            strength = "VERY WEAK"
        
        return {'strength': strength, 'score': score, 'feedback': feedback}


# ==================== QR CODE GENERATOR ====================
class QRCodeGenerator:
    def __init__(self):
        self.qr = qrcode.QRCode(version=1, box_size=10, border=5)
    
    def generate_qr(self, data):
        self.qr.clear()
        self.qr.add_data(data)
        self.qr.make(fit=True)
        img = self.qr.make_image(fill_color="black", back_color="white")
        return img
    
    def generate_qr_with_logo(self, data, logo_path=None):
        img = self.generate_qr(data)
        if logo_path:
            try:
                logo = Image.open(logo_path)
                qr_width, qr_height = img.size
                logo_size = qr_width // 4
                logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
                pos = ((qr_width - logo_size) // 2, (qr_height - logo_size) // 2)
                img.paste(logo, pos)
            except:
                pass
        return img


# ==================== USERNAME SEARCHER ====================
class UsernameSearcher:
    def __init__(self):
        self.platforms = {
            'Twitter (X)': {'url': 'https://twitter.com/{}', 'detection_type': 'aggressive', 'not_found_indicators': ['this account doesn’t exist', 'page not found'], 'icon': '🐦', 'color': '#1DA1F2'},
            'Instagram': {'url': 'https://www.instagram.com/{}/', 'detection_type': 'aggressive', 'not_found_indicators': ['sorry, this page isn\'t available'], 'icon': '📸', 'color': '#E4405F'},
            'TikTok': {'url': 'https://www.tiktok.com/@{}', 'detection_type': 'aggressive', 'not_found_indicators': ['couldn\'t find this account'], 'icon': '🎵', 'color': '#000000'},
            'Reddit': {'url': 'https://www.reddit.com/user/{}', 'api_url': 'https://www.reddit.com/user/{}/about.json', 'detection_type': 'json_api', 'icon': '🤖', 'color': '#FF4500'},
            'GitHub': {'url': 'https://github.com/{}', 'api_url': 'https://api.github.com/users/{}', 'detection_type': 'json_api_aggressive', 'icon': '💻', 'color': '#181717'},
            'YouTube': {'url': 'https://www.youtube.com/@{}', 'detection_type': 'youtube_aggressive', 'not_found_indicators': ['this page isn\'t available'], 'icon': '📺', 'color': '#FF0000'},
            'Telegram': {'url': 'https://t.me/{}', 'detection_type': 'aggressive', 'not_found_indicators': ['username doesn\'t exist'], 'icon': '📱', 'color': '#26A5E4'},
            'Discord': {'url': 'https://discord.com/users/{}', 'detection_type': 'aggressive', 'not_found_indicators': ['non-existent'], 'icon': '💬', 'color': '#5865F2'},
            'Spotify': {'url': 'https://open.spotify.com/user/{}', 'detection_type': 'aggressive', 'not_found_indicators': ['not found'], 'icon': '🎧', 'color': '#1DB954'},
            'guns.lol': {'url': 'https://guns.lol/{}', 'detection_type': 'aggressive', 'not_found_indicators': ['not found', 'doesn\'t exist'], 'icon': '🔫', 'color': '#FF4444'}
        }
        self.is_searching = False
    
    def check_username(self, platform_name: str, platform_info: Dict, username: str) -> Tuple[str, bool, str]:
        url = platform_info['url'].format(username)
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                response_text = response.text.lower()
                not_found_indicators = platform_info.get('not_found_indicators', [])
                for indicator in not_found_indicators:
                    if indicator.lower() in response_text:
                        return platform_name, False, url
                return platform_name, True, url
            elif response.status_code == 404:
                return platform_name, False, url
            else:
                return platform_name, True, url
        except:
            return platform_name, True, url
    
    def search_all(self, username: str, progress_callback=None) -> Dict:
        results = {}
        total_platforms = len(self.platforms)
        for idx, (platform_name, platform_info) in enumerate(self.platforms.items()):
            if not self.is_searching:
                break
            if progress_callback:
                progress_callback(platform_name, idx + 1, total_platforms)
            platform_name, exists, url = self.check_username(platform_name, platform_info, username)
            results[platform_name] = {'exists': exists, 'url': url}
            time.sleep(0.15)
        return results


# ==================== USERNAME AVAILABILITY CHECKER ====================
class UsernameAvailabilityChecker:
    def __init__(self):
        self.timeout = 10
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.platforms = {
            "TikTok": self.check_tiktok, "Instagram": self.check_instagram, "Discord": self.check_discord,
            "GitHub": self.check_github, "Reddit": self.check_reddit, "Twitter": self.check_twitter,
            "Twitch": self.check_twitch, "Roblox": self.check_roblox, "YouTube": self.check_youtube,
            "Telegram": self.check_telegram, "Spotify": self.check_spotify, "guns.lol": self.check_guns_lol
        }
    
    def check_username(self, username: str, callback=None) -> Dict[str, Tuple[bool, str]]:
        results = {}
        total_platforms = len(self.platforms)
        for idx, (platform, check_func) in enumerate(self.platforms.items()):
            try:
                if callback:
                    callback(platform, "checking", idx + 1, total_platforms)
                is_available, message = check_func(username)
                results[platform] = (is_available, message)
                if callback:
                    callback(platform, "completed", idx + 1, total_platforms)
                time.sleep(0.5)
            except Exception as e:
                results[platform] = (False, f"Error: {str(e)}")
                if callback:
                    callback(platform, "error", idx + 1, total_platforms)
        return results
    
    def check_tiktok(self, username: str) -> Tuple[bool, str]:
        url = f"https://www.tiktok.com/@{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 404:
                return True, "Available"
            elif response.status_code == 200:
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_instagram(self, username: str) -> Tuple[bool, str]:
        url = f"https://www.instagram.com/{username}/"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 404:
                return True, "Available"
            elif "Page Not Found" in response.text:
                return True, "Available"
            elif response.status_code == 200:
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_discord(self, username: str) -> Tuple[bool, str]:
        try:
            url = f"https://discord.com/users/{username}"
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            if response.status_code == 404:
                return True, "Available"
            return False, "Taken"
        except:
            return False, "Could not verify"
    
    def check_github(self, username: str) -> Tuple[bool, str]:
        url = f"https://github.com/{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 404:
                return True, "Available"
            elif response.status_code == 200:
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_reddit(self, username: str) -> Tuple[bool, str]:
        url = f"https://www.reddit.com/user/{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 404:
                return True, "Available"
            elif response.status_code == 200:
                if "user not found" in response.text.lower():
                    return True, "Available"
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_twitter(self, username: str) -> Tuple[bool, str]:
        nitter_instances = ["https://nitter.net", "https://nitter.poast.org"]
        for instance in nitter_instances:
            try:
                url = f"{instance}/{username}"
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                if response.status_code == 404:
                    return True, "Available"
                elif response.status_code == 200:
                    if "doesn't exist" in response.text:
                        return True, "Available"
                    return False, "Taken"
            except:
                continue
        return False, "Could not verify"
    
    def check_twitch(self, username: str) -> Tuple[bool, str]:
        url = f"https://www.twitch.tv/{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 404:
                return True, "Available"
            elif response.status_code == 200:
                if "Sorry" in response.text and "time machine" in response.text:
                    return True, "Available"
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_roblox(self, username: str) -> Tuple[bool, str]:
        try:
            api_url = f"https://users.roblox.com/v1/usernames/users"
            payload = {"usernames": [username]}
            response = requests.post(api_url, json=payload, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data.get("data"):
                    return False, "Taken"
                return True, "Available"
            return False, "Could not verify"
        except:
            return False, "Could not verify"
    
    def check_youtube(self, username: str) -> Tuple[bool, str]:
        url = f"https://www.youtube.com/@{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            if response.status_code == 200:
                if "this page isn't available" in response.text.lower():
                    return True, "Available"
                return False, "Taken"
            return True, "Available"
        except:
            return False, "Could not verify"
    
    def check_telegram(self, username: str) -> Tuple[bool, str]:
        url = f"https://t.me/{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 404:
                return True, "Available"
            elif "username doesn't exist" in response.text:
                return True, "Available"
            elif response.status_code == 200:
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_spotify(self, username: str) -> Tuple[bool, str]:
        url = f"https://open.spotify.com/user/{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 404:
                return True, "Available"
            elif response.status_code == 200:
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"
    
    def check_guns_lol(self, username: str) -> Tuple[bool, str]:
        url = f"https://guns.lol/{username}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            if response.status_code == 404:
                return True, "Available"
            elif response.status_code == 200:
                if "not found" in response.text.lower():
                    return True, "Available"
                return False, "Taken"
            return False, f"Unknown"
        except:
            return False, "Could not verify"


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
    
    def export_messages(self, messages, channel_name, export_format, include_reactions=True):
        exported = []
        export_dir = Path("discord_exports")
        export_dir.mkdir(exist_ok=True)
        processed = []
        for msg in messages:
            processed.append({
                'id': msg['id'], 'author': msg['author']['username'], 'content': msg['content'],
                'timestamp': datetime.fromisoformat(msg['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S'),
                'channel': channel_name
            })
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
                writer = csv.DictWriter(fp, fieldnames=['id', 'author', 'content', 'timestamp', 'channel'])
                writer.writeheader()
                for msg in processed:
                    writer.writerow({k: msg[k] for k in ['id', 'author', 'content', 'timestamp', 'channel']})
            exported.append(f)
        
        if export_format in ['txt', 'all']:
            f = export_dir / f"{safe_name}_{ts}.txt"
            with open(f, 'w', encoding='utf-8') as fp:
                fp.write(f"#{channel_name}\n{'='*40}\n")
                for msg in processed:
                    fp.write(f"[{msg['timestamp']}] {msg['author']}: {msg['content']}\n")
            exported.append(f)
        
        if export_format in ['html', 'all']:
            f = export_dir / f"{safe_name}_{ts}.html"
            with open(f, 'w', encoding='utf-8') as fp:
                fp.write(f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Discord Export - {channel_name}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e1e; color: #e0e0e0; margin: 0; padding: 20px; }}
.container {{ max-width: 800px; margin: 0 auto; background: #2d2d2d; border: 1px solid #00ff00; border-radius: 5px; overflow: hidden; }}
.header {{ background: #2d2d2d; padding: 15px; border-bottom: 1px solid #00ff00; }}
.message {{ padding: 10px 15px; border-bottom: 1px solid #3a3a3a; }}
.message:hover {{ background: #3a3a3a; }}
.author {{ font-weight: bold; color: #00ff00; margin-right: 10px; }}
.timestamp {{ font-size: 11px; color: #888888; }}
.content {{ margin-top: 5px; white-space: pre-wrap; }}
</style>
</head>
<body>
<div class="container"><div class="header"><h1 style="color: #00ff00;">#{channel_name}</h1>
<div>Total Messages: {len(processed)}</div><div>Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div></div>""")
                for msg in processed:
                    content = msg['content'].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
                    fp.write(f'<div class="message"><div><span class="author">{msg["author"]}</span><span class="timestamp">{msg["timestamp"]}</span></div><div class="content">{content if content else "<i>No text content</i>"}</div></div>')
                fp.write("</div></body></html>")
            exported.append(f)
        return exported
    
    def export(self, token, channel_id, message_limit, export_format, include_reactions, progress_callback=None, log_callback=None):
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
            exported_files = self.export_messages(messages, channel_name, export_format, include_reactions)
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
        self.window.title("LARPSEC")
        self.window.geometry("1400x950")
        self.window.minsize(1200, 850)
        
        self.bg_color = "#1e1e1e"
        self.accent_color = "#00ff00"
        
        self.username_searcher = UsernameSearcher()
        self.availability_checker = UsernameAvailabilityChecker()
        self.discord_exporter = DiscordExporter()
        self.contact_analyzer = ContactInfoAnalyzer()
        self.reverse_image_search = ReverseImageSearch()
        self.url_scanner = URLScanner()
        self.password_generator = PasswordGenerator()
        self.qr_generator = QRCodeGenerator()
        
        self.setup_ui()
    
    def setup_ui(self):
        self.main_container = ctk.CTkFrame(self.window)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.header_frame = ctk.CTkFrame(self.main_container)
        self.header_frame.pack(fill="x", padx=10, pady=(10, 20))
        
        # Green title
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="LARPSEC", 
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=self.accent_color
        )
        self.title_label.pack(pady=(10, 5))
        
        self.subtitle_label = ctk.CTkLabel(
            self.header_frame, 
            text="made by @crushable | property of 414", 
            font=ctk.CTkFont(size=12)
        )
        self.subtitle_label.pack()
        
        # New line with bug reporting info
        self.bug_report_label = ctk.CTkLabel(
            self.header_frame,
            text="find any bugs? dm @crushable on discord",
            font=ctk.CTkFont(size=11),
            text_color="#888888"
        )
        self.bug_report_label.pack(pady=(5, 0))
        
        self.tabview = ctk.CTkTabview(self.main_container)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab order with Discord Exporter in the center (position 4 out of 9)
        self.searcher_tab = self.tabview.add("🔍 User Lookup")
        self.availability_tab = self.tabview.add("✅ Availability Checker")
        self.iplookup_tab = self.tabview.add("🌐 IP Lookup")
        self.contact_tab = self.tabview.add("📧 Email/Phone Lookup")
        self.exporter_tab = self.tabview.add("📥 Discord Exporter")  # Center position
        self.reverse_tab = self.tabview.add("🖼️ Reverse Image Search")
        self.url_tab = self.tabview.add("🔗 URL Scanner")
        self.password_tab = self.tabview.add("🔐 Password Generator")
        self.qr_tab = self.tabview.add("📱 QR Code Generator")
        
        self.setup_searcher_tab()
        self.setup_availability_tab()
        self.setup_iplookup_tab()
        self.setup_contact_tab()
        self.setup_exporter_tab()
        self.setup_reverse_tab()
        self.setup_url_tab()
        self.setup_password_tab()
        self.setup_qr_tab()
        
        self.status_frame = ctk.CTkFrame(self.main_container)
        self.status_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="● Ready", font=ctk.CTkFont(size=11), anchor="w")
        self.status_label.pack(side="left", padx=5)
        
        self.timestamp_label = ctk.CTkLabel(self.status_frame, text="", font=ctk.CTkFont(size=11), anchor="e")
        self.timestamp_label.pack(side="right", padx=5)
    
    def setup_reverse_tab(self):
        """Setup Reverse Image Search tab"""
        input_frame = ctk.CTkFrame(self.reverse_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.image_url_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter image URL...", font=ctk.CTkFont(size=14), height=45)
        self.image_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.search_url_btn = ctk.CTkButton(input_frame, text="🔍 Search by URL", command=self.search_image_by_url, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.search_url_btn.pack(side="right", padx=(0, 5))
        
        self.upload_btn = ctk.CTkButton(input_frame, text="📁 Upload Image", command=self.upload_image, height=45)
        self.upload_btn.pack(side="right")
        
        results_frame = ctk.CTkFrame(self.reverse_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.reverse_results_text = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=12))
        self.reverse_results_text.pack(fill="both", expand=True)
        
        info_label = ctk.CTkLabel(self.reverse_tab, text="ℹ️ Search for similar images across Google, Bing, Yandex, and Tineye", font=ctk.CTkFont(size=11), text_color="#888888")
        info_label.pack(pady=5)
    
    def search_image_by_url(self):
        url = self.image_url_entry.get().strip()
        if not url:
            self.status_label.configure(text="⚠ Please enter an image URL", text_color="orange")
            return
        
        self.reverse_results_text.delete("1.0", "end")
        self.reverse_results_text.insert("1.0", f"Searching for image: {url}\n\n")
        
        results = self.reverse_image_search.search_by_url(url)
        
        if 'error' in results:
            self.reverse_results_text.insert("end", f"Error: {results['error']}\n")
            return
        
        for engine, search_url in results.items():
            self.reverse_results_text.insert("end", f"🔍 {engine}:\n  {search_url}\n\n")
        
        self.status_label.configure(text=f"✓ Found {len(results)} search engines", text_color="green")
    
    def upload_image(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg *.jpeg *.png *.gif *.bmp")])
        if file_path:
            self.status_label.configure(text="📤 Uploading image...", text_color="green")
            results = self.reverse_image_search.search_by_file(file_path)
            self.reverse_results_text.delete("1.0", "end")
            if 'error' in results:
                self.reverse_results_text.insert("1.0", f"Error: {results['error']}\n")
            else:
                self.reverse_results_text.insert("1.0", f"Uploaded: {os.path.basename(file_path)}\n\n")
                for engine, search_url in results.items():
                    self.reverse_results_text.insert("end", f"🔍 {engine}:\n  {search_url}\n\n")
            self.status_label.configure(text="✓ Upload complete", text_color="green")
    
    def setup_url_tab(self):
        """Setup URL Scanner tab"""
        input_frame = ctk.CTkFrame(self.url_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.url_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter URL to scan...", font=ctk.CTkFont(size=14), height=45)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.scan_url_btn = ctk.CTkButton(input_frame, text="🔍 Scan URL", command=self.scan_url, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.scan_url_btn.pack(side="right")
        
        results_frame = ctk.CTkFrame(self.url_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.url_results_text = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=12))
        self.url_results_text.pack(fill="both", expand=True)
        
        info_label = ctk.CTkLabel(self.url_tab, text="ℹ️ Scans URLs for safety risks, suspicious patterns, and accessibility", font=ctk.CTkFont(size=11), text_color="#888888")
        info_label.pack(pady=5)
    
    def scan_url(self):
        url = self.url_entry.get().strip()
        if not url:
            self.status_label.configure(text="⚠ Please enter a URL", text_color="orange")
            return
        
        self.url_results_text.delete("1.0", "end")
        self.url_results_text.insert("1.0", f"Scanning URL: {url}\n\n")
        
        results = self.url_scanner.scan_url(url)
        
        self.url_results_text.insert("end", "🔒 SAFETY CHECKS\n" + "-" * 40 + "\n")
        safety = results.get('safety_checks', {})
        self.url_results_text.insert("end", f"  Domain: {safety.get('domain', 'Unknown')}\n")
        self.url_results_text.insert("end", f"  Suspicious Keywords: {'⚠️ Yes' if safety.get('suspicious_keywords') else 'No'}\n")
        self.url_results_text.insert("end", f"  Uses IP Address: {'⚠️ Yes' if safety.get('uses_ip_address') else 'No'}\n")
        self.url_results_text.insert("end", f"  URL Length: {safety.get('url_length', 0)} characters {'⚠️' if safety.get('is_long_url') else ''}\n")
        self.url_results_text.insert("end", f"  Subdomains: {safety.get('subdomain_count', 0)} {'⚠️' if safety.get('excessive_subdomains') else ''}\n")
        self.url_results_text.insert("end", f"  Accessible: {'✅ Yes' if safety.get('is_accessible') else '❌ No'}\n\n")
        
        self.url_results_text.insert("end", "⚠️ REPUTATION\n" + "-" * 40 + "\n")
        reputation = results.get('reputation', {})
        risk_level = reputation.get('risk_level', 'UNKNOWN')
        if risk_level == "HIGH RISK":
            self.url_results_text.insert("end", f"  Risk Level: {risk_level} 🔴\n", "error")
        elif risk_level == "MEDIUM RISK":
            self.url_results_text.insert("end", f"  Risk Level: {risk_level} 🟡\n", "warning")
        elif risk_level == "LOW RISK":
            self.url_results_text.insert("end", f"  Risk Level: {risk_level} 🟢\n")
        else:
            self.url_results_text.insert("end", f"  Risk Level: {risk_level} ✅\n")
        self.url_results_text.insert("end", "\n")
        
        self.url_results_text.insert("end", "🔧 TECHNICAL DETAILS\n" + "-" * 40 + "\n")
        tech = results.get('technical_details', {})
        self.url_results_text.insert("end", f"  Scheme: {tech.get('scheme', 'Unknown')}\n")
        self.url_results_text.insert("end", f"  Domain: {tech.get('netloc', 'Unknown')}\n")
        self.url_results_text.insert("end", f"  Status Code: {tech.get('status_code', 'N/A')}\n")
        if tech.get('redirect_count'):
            self.url_results_text.insert("end", f"  Redirects: {tech.get('redirect_count')}\n")
        if tech.get('final_url') and tech.get('final_url') != url:
            self.url_results_text.insert("end", f"  Final URL: {tech.get('final_url')}\n")
        
        self.status_label.configure(text=f"✓ Scan completed", text_color="green")
    
    def setup_password_tab(self):
        """Setup Password Generator tab"""
        controls_frame = ctk.CTkFrame(self.password_tab)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        length_frame = ctk.CTkFrame(controls_frame)
        length_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(length_frame, text="Password Length:", font=ctk.CTkFont(size=12)).pack(side="left", padx=5)
        self.password_length = ctk.CTkEntry(length_frame, width=80, placeholder_text="16")
        self.password_length.pack(side="left", padx=5)
        self.password_length.insert(0, "16")
        
        options_frame = ctk.CTkFrame(controls_frame)
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        
        ctk.CTkCheckBox(options_frame, text="Lowercase (a-z)", variable=self.use_lower).pack(side="left", padx=5)
        ctk.CTkCheckBox(options_frame, text="Uppercase (A-Z)", variable=self.use_upper).pack(side="left", padx=5)
        ctk.CTkCheckBox(options_frame, text="Numbers (0-9)", variable=self.use_digits).pack(side="left", padx=5)
        ctk.CTkCheckBox(options_frame, text="Symbols (!@#)", variable=self.use_symbols).pack(side="left", padx=5)
        
        button_frame = ctk.CTkFrame(controls_frame)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.generate_btn = ctk.CTkButton(button_frame, text="🔐 Generate Password", command=self.generate_password, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        self.generate_btn.pack(side="left", padx=5)
        
        self.copy_pass_btn = ctk.CTkButton(button_frame, text="📋 Copy", command=self.copy_password, height=40)
        self.copy_pass_btn.pack(side="left", padx=5)
        
        results_frame = ctk.CTkFrame(self.password_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.password_display = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=14, weight="bold"), height=80)
        self.password_display.pack(fill="x", padx=10, pady=5)
        
        self.strength_display = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=12), height=150)
        self.strength_display.pack(fill="both", expand=True, padx=10, pady=5)
    
    def generate_password(self):
        try:
            length = int(self.password_length.get())
        except:
            length = 16
        
        password = self.password_generator.generate_password(
            length=length,
            use_lower=self.use_lower.get(),
            use_upper=self.use_upper.get(),
            use_digits=self.use_digits.get(),
            use_symbols=self.use_symbols.get()
        )
        
        self.password_display.delete("1.0", "end")
        self.password_display.insert("1.0", password)
        
        strength = self.password_generator.check_strength(password)
        self.strength_display.delete("1.0", "end")
        self.strength_display.insert("1.0", f"Strength: {strength['strength']}\n\n")
        self.strength_display.insert("end", "\n".join(strength['feedback']))
        
        self.status_label.configure(text="✓ Password generated", text_color="green")
    
    def copy_password(self):
        password = self.password_display.get("1.0", "end-1c")
        if password.strip():
            self.window.clipboard_clear()
            self.window.clipboard_append(password)
            self.status_label.configure(text="✓ Password copied to clipboard", text_color="green")
    
    def setup_qr_tab(self):
        """Setup QR Code Generator tab"""
        input_frame = ctk.CTkFrame(self.qr_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.qr_data_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter text or URL to encode...", font=ctk.CTkFont(size=14), height=45)
        self.qr_data_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.generate_qr_btn = ctk.CTkButton(input_frame, text="📱 Generate QR Code", command=self.generate_qr_code, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.generate_qr_btn.pack(side="right")
        
        qr_frame = ctk.CTkFrame(self.qr_tab)
        qr_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.qr_label = ctk.CTkLabel(qr_frame, text="QR Code will appear here", font=ctk.CTkFont(size=12))
        self.qr_label.pack(expand=True)
        
        button_frame = ctk.CTkFrame(self.qr_tab)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.save_qr_btn = ctk.CTkButton(button_frame, text="💾 Save QR Code", command=self.save_qr_code, height=35)
        self.save_qr_btn.pack(side="left", padx=5)
        
        self.copy_qr_btn = ctk.CTkButton(button_frame, text="📋 Copy Data", command=self.copy_qr_data, height=35)
        self.copy_qr_btn.pack(side="left", padx=5)
        
        self.current_qr_image = None
    
    def generate_qr_code(self):
        data = self.qr_data_entry.get().strip()
        if not data:
            self.status_label.configure(text="⚠ Please enter text or URL", text_color="orange")
            return
        
        img = self.qr_generator.generate_qr(data)
        
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)
        
        photo = ImageTk.PhotoImage(img)
        self.qr_label.configure(image=photo, text="")
        self.qr_label.image = photo
        self.current_qr_image = img
        
        self.status_label.configure(text="✓ QR Code generated", text_color="green")
    
    def save_qr_code(self):
        if self.current_qr_image:
            from tkinter import filedialog
            file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if file_path:
                self.current_qr_image.save(file_path)
                self.status_label.configure(text=f"✓ QR Code saved to {file_path}", text_color="green")
        else:
            self.status_label.configure(text="⚠ Generate a QR code first", text_color="orange")
    
    def copy_qr_data(self):
        data = self.qr_data_entry.get().strip()
        if data:
            self.window.clipboard_clear()
            self.window.clipboard_append(data)
            self.status_label.configure(text="✓ Data copied to clipboard", text_color="green")
        else:
            self.status_label.configure(text="⚠ No data to copy", text_color="orange")
    
    # ==================== IP Lookup Methods ====================
    def setup_iplookup_tab(self):
        input_frame = ctk.CTkFrame(self.iplookup_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.ip_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter IP address to lookup (e.g., 8.8.8.8)...", font=ctk.CTkFont(size=14), height=45)
        self.ip_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.ip_entry.bind("<Return>", lambda e: self.start_ip_lookup())
        
        self.ip_lookup_button = ctk.CTkButton(input_frame, text="🌐 Lookup IP", command=self.start_ip_lookup, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.ip_lookup_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.iplookup_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.ip_progress_label = ctk.CTkLabel(progress_frame, text="Ready to lookup IP", font=ctk.CTkFont(size=12))
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
        
        self.copy_ip_btn = ctk.CTkButton(button_frame, text="📋 Copy Results", command=self.copy_ip_results, height=35)
        self.copy_ip_btn.pack(side="left", padx=5)
        
        self.clear_ip_btn = ctk.CTkButton(button_frame, text="🗑 Clear Results", command=self.clear_ip_results, height=35)
        self.clear_ip_btn.pack(side="left", padx=5)
    
    def start_ip_lookup(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            self.status_label.configure(text="⚠ Please enter an IP address", text_color="orange")
            return
        
        self.ip_lookup_button.configure(text="⏹ Looking up...", state="disabled")
        self.ip_entry.configure(state="disabled")
        self.ip_progress_bar.set(0)
        self.ip_progress_label.configure(text="Starting IP lookup...")
        self.status_label.configure(text=f"🔍 Looking up IP: {ip}", text_color="green")
        self.ip_results_text.delete("1.0", "end")
        
        lookup_thread = threading.Thread(target=self.perform_ip_lookup, args=(ip,))
        lookup_thread.daemon = True
        lookup_thread.start()
    
    def perform_ip_lookup(self, ip: str):
        try:
            self.window.after(0, self.update_ip_progress, 20, "Fetching IP information...")
            gatherer = IPInformationGatherer(ip)
            results = gatherer.get_all_info()
            self.window.after(0, self.display_ip_results, results)
            self.window.after(0, self.status_label.configure, {"text": f"✓ IP lookup completed for {ip}", "text_color": "green"})
            self.window.after(0, self.timestamp_label.configure, {"text": datetime.now().strftime("%H:%M:%S")})
        except Exception as e:
            self.window.after(0, self.show_ip_error, str(e))
        finally:
            self.window.after(0, self.ip_lookup_complete)
    
    def update_ip_progress(self, percent: int, status: str):
        self.ip_progress_bar.set(percent / 100)
        self.ip_progress_label.configure(text=status)
    
    def display_ip_results(self, results: Dict):
        self.ip_results_text.delete("1.0", "end")
        if 'error' in results:
            self.ip_results_text.insert("1.0", f"Error: {results['error']}\n")
            return
        
        self.ip_results_text.tag_config("header", foreground="#00ff00")
        self.ip_results_text.tag_config("section", foreground="#00ff00")
        
        header = f"{'='*70}\nIP INFORMATION REPORT FOR: {results.get('ip_address', 'Unknown')}\n{'='*70}\n\n"
        self.ip_results_text.insert("end", header, "header")
        
        self.ip_results_text.insert("end", "[Basic Information]\n", "section")
        self.ip_results_text.insert("end", f"  IP Type: {results.get('ip_type', 'Unknown')}\n")
        self.ip_results_text.insert("end", f"  Hostname: {results.get('hostname', 'Unknown')}\n\n")
        
        self.ip_results_text.insert("end", "[IP-API.com Information]\n", "section")
        ip_api = results.get('ip_api', {})
        if 'error' not in ip_api:
            for key, value in ip_api.items():
                if value and value != 'Unknown' and value != False:
                    self.ip_results_text.insert("end", f"  {key.replace('_', ' ').title()}: {value}\n")
        self.ip_results_text.insert("end", "\n")
        
        footer = f"\n{'='*70}\nLookup completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        self.ip_results_text.insert("end", footer)
    
    def show_ip_error(self, error_message: str):
        self.status_label.configure(text=f"⚠ Error: {error_message}", text_color="red")
    
    def ip_lookup_complete(self):
        self.ip_lookup_button.configure(text="🌐 Lookup IP", command=self.start_ip_lookup, state="normal")
        self.ip_entry.configure(state="normal")
        self.ip_progress_label.configure(text="Lookup complete")
        self.ip_progress_bar.set(1.0)
        self.window.after(2000, lambda: self.ip_progress_bar.set(0))
    
    def copy_ip_results(self):
        results = self.ip_results_text.get("1.0", "end-1c")
        if results.strip():
            self.window.clipboard_clear()
            self.window.clipboard_append(results)
            self.status_label.configure(text="✓ Results copied to clipboard", text_color="green")
            self.window.after(2000, lambda: self.status_label.configure(text="● Ready", text_color="white"))
    
    def clear_ip_results(self):
        self.ip_results_text.delete("1.0", "end")
        self.status_label.configure(text="● Results cleared", text_color="white")
    
    # ==================== Contact Methods ====================
    def setup_contact_tab(self):
        input_frame = ctk.CTkFrame(self.contact_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.contact_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter email address or phone number...", font=ctk.CTkFont(size=14), height=45)
        self.contact_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.contact_entry.bind("<Return>", lambda e: self.start_contact_lookup())
        
        self.contact_button = ctk.CTkButton(input_frame, text="📧 Lookup", command=self.start_contact_lookup, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.contact_button.pack(side="right")
        
        country_frame = ctk.CTkFrame(self.contact_tab)
        country_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(country_frame, text="Default Country (for phone numbers):", font=ctk.CTkFont(size=12)).pack(side="left", padx=5)
        self.country_entry = ctk.CTkEntry(country_frame, placeholder_text="e.g., US, GB, IN", width=80, height=30)
        self.country_entry.pack(side="left", padx=5)
        self.country_entry.insert(0, "US")
        
        progress_frame = ctk.CTkFrame(self.contact_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.contact_progress_label = ctk.CTkLabel(progress_frame, text="Ready to lookup", font=ctk.CTkFont(size=12))
        self.contact_progress_label.pack()
        
        self.contact_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.contact_progress_bar.pack(fill="x", pady=(5, 0))
        self.contact_progress_bar.set(0)
        
        results_frame = ctk.CTkFrame(self.contact_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.contact_results_text = ctk.CTkTextbox(results_frame, font=ctk.CTkFont(size=12))
        self.contact_results_text.pack(fill="both", expand=True)
        
        button_frame = ctk.CTkFrame(self.contact_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        self.copy_contact_btn = ctk.CTkButton(button_frame, text="📋 Copy Results", command=self.copy_contact_results, height=35)
        self.copy_contact_btn.pack(side="left", padx=5)
        
        self.clear_contact_btn = ctk.CTkButton(button_frame, text="🗑 Clear Results", command=self.clear_contact_results, height=35)
        self.clear_contact_btn.pack(side="left", padx=5)
        
        self.save_contact_btn = ctk.CTkButton(button_frame, text="💾 Save to File", command=self.save_contact_results, height=35)
        self.save_contact_btn.pack(side="left", padx=5)
    
    def start_contact_lookup(self):
        contact_input = self.contact_entry.get().strip()
        if not contact_input:
            self.status_label.configure(text="⚠ Please enter an email or phone number", text_color="orange")
            return
        
        input_type = self.contact_analyzer.identify_input_type(contact_input)
        if input_type == 'unknown':
            self.status_label.configure(text="⚠ Could not identify input type", text_color="orange")
            return
        
        self.contact_button.configure(text="⏹ Looking up...", state="disabled")
        self.contact_entry.configure(state="disabled")
        self.contact_progress_bar.set(0)
        self.contact_progress_label.configure(text="Starting lookup...")
        self.status_label.configure(text=f"🔍 Looking up: {contact_input}", text_color="green")
        self.contact_results_text.delete("1.0", "end")
        
        lookup_thread = threading.Thread(target=self.perform_contact_lookup, args=(contact_input, input_type))
        lookup_thread.daemon = True
        lookup_thread.start()
    
    def perform_contact_lookup(self, contact_input: str, input_type: str):
        try:
            self.window.after(0, self.update_contact_progress, 20, "Fetching information...")
            if input_type == 'email':
                results = self.contact_analyzer.analyze_email(contact_input)
                self.window.after(0, self.display_email_results, results)
            else:
                country = self.country_entry.get().strip().upper() or 'US'
                results = self.contact_analyzer.analyze_phone(contact_input, country)
                self.window.after(0, self.display_phone_results, results)
            self.window.after(0, self.status_label.configure, {"text": f"✓ Lookup completed", "text_color": "green"})
        except Exception as e:
            self.window.after(0, self.show_contact_error, str(e))
        finally:
            self.window.after(0, self.contact_lookup_complete)
    
    def update_contact_progress(self, percent: int, status: str):
        self.contact_progress_bar.set(percent / 100)
        self.contact_progress_label.configure(text=status)
    
    def display_email_results(self, results: Dict):
        self.contact_results_text.delete("1.0", "end")
        self.contact_results_text.tag_config("header", foreground="#00ff00")
        self.contact_results_text.tag_config("section", foreground="#00ff00")
        
        header = f"{'='*70}\nEMAIL ANALYSIS REPORT\nEmail: {results.get('email', 'Unknown')}\n{'='*70}\n\n"
        self.contact_results_text.insert("end", header, "header")
        
        validation = results.get('validation', {})
        self.contact_results_text.insert("end", "📧 Email Validation\n", "section")
        self.contact_results_text.insert("end", f"  Format: {'✅ Valid' if validation.get('format_valid') else '❌ Invalid'}\n")
        self.contact_results_text.insert("end", f"  MX Records: {'✅ Yes' if validation.get('mx_records_exist') else '❌ No'}\n")
        
        breaches = results.get('data_breaches', {})
        if breaches.get('breached'):
            self.contact_results_text.insert("end", f"\n⚠️ This email has been in {breaches['breach_count']} data breaches!\n", "warning")
        
        gravatar = results.get('gravatar', {})
        if gravatar.get('has_gravatar'):
            self.contact_results_text.insert("end", f"\n👤 Gravatar: {gravatar.get('name', 'Profile found')}\n", "success")
    
    def display_phone_results(self, results: Dict):
        self.contact_results_text.delete("1.0", "end")
        self.contact_results_text.tag_config("header", foreground="#00ff00")
        self.contact_results_text.tag_config("section", foreground="#00ff00")
        
        header = f"{'='*70}\nPHONE NUMBER ANALYSIS REPORT\nNumber: {results.get('phone_number', 'Unknown')}\n{'='*70}\n\n"
        self.contact_results_text.insert("end", header, "header")
        
        if 'error' in results:
            self.contact_results_text.insert("end", f"Error: {results['error']}\n")
            return
        
        parsed = results.get('parsed_info', {})
        self.contact_results_text.insert("end", "📱 Basic Information\n", "section")
        self.contact_results_text.insert("end", f"  Country Code: +{parsed.get('country_code', 'Unknown')}\n")
        self.contact_results_text.insert("end", f"  Valid: {'✅ Yes' if parsed.get('is_valid_number') else '❌ No'}\n\n")
        
        carrier_info = results.get('carrier_info', {})
        self.contact_results_text.insert("end", "📡 Carrier Information\n", "section")
        self.contact_results_text.insert("end", f"  Carrier: {carrier_info.get('name', 'Unknown')}\n")
        self.contact_results_text.insert("end", f"  Type: {carrier_info.get('number_type', 'Unknown')}\n\n")
        
        location = results.get('location_info', {})
        self.contact_results_text.insert("end", "📍 Location Information\n", "section")
        self.contact_results_text.insert("end", f"  Location: {location.get('description', 'Unknown')}\n")
        self.contact_results_text.insert("end", f"  Country: {location.get('country', 'Unknown')}\n")
    
    def show_contact_error(self, error_message: str):
        self.status_label.configure(text=f"⚠ Error: {error_message}", text_color="red")
    
    def contact_lookup_complete(self):
        self.contact_button.configure(text="📧 Lookup", command=self.start_contact_lookup, state="normal")
        self.contact_entry.configure(state="normal")
        self.contact_progress_label.configure(text="Lookup complete")
        self.contact_progress_bar.set(1.0)
        self.window.after(2000, lambda: self.contact_progress_bar.set(0))
    
    def copy_contact_results(self):
        results = self.contact_results_text.get("1.0", "end-1c")
        if results.strip():
            self.window.clipboard_clear()
            self.window.clipboard_append(results)
            self.status_label.configure(text="✓ Results copied to clipboard", text_color="green")
    
    def clear_contact_results(self):
        self.contact_results_text.delete("1.0", "end")
        self.status_label.configure(text="● Results cleared", text_color="white")
    
    def save_contact_results(self):
        results = self.contact_results_text.get("1.0", "end-1c")
        if results.strip():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"contact_lookup_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(results)
            self.status_label.configure(text=f"✓ Results saved to {filename}", text_color="green")
    
    # ==================== Searcher Methods ====================
    def setup_searcher_tab(self):
        search_frame = ctk.CTkFrame(self.searcher_tab)
        search_frame.pack(fill="x", padx=10, pady=10)
        
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Enter username to search...", font=ctk.CTkFont(size=14), height=45)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.search_entry.bind("<Return>", lambda e: self.start_username_search())
        
        self.search_button = ctk.CTkButton(search_frame, text="🔍 Search", command=self.start_username_search, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.search_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.searcher_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.search_progress_label = ctk.CTkLabel(progress_frame, text="Ready to search", font=ctk.CTkFont(size=12))
        self.search_progress_label.pack()
        
        self.search_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.search_progress_bar.pack(fill="x", pady=(5, 0))
        self.search_progress_bar.set(0)
        
        results_tabview = ctk.CTkTabview(self.searcher_tab)
        results_tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.found_tab = results_tabview.add("✅ Found Accounts")
        self.not_found_tab = results_tabview.add("❌ Not Found")
        self.all_results_tab = results_tabview.add("📊 All Results")
        
        self.found_scroll = ctk.CTkScrollableFrame(self.found_tab)
        self.found_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.not_found_scroll = ctk.CTkScrollableFrame(self.not_found_tab)
        self.not_found_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.all_results_text = ctk.CTkTextbox(self.all_results_tab, font=ctk.CTkFont(size=12))
        self.all_results_text.pack(fill="both", expand=True, padx=10, pady=10)
    
    def start_username_search(self):
        username = self.search_entry.get().strip()
        if not username:
            self.status_label.configure(text="⚠ Please enter a username", text_color="orange")
            return
        
        self.clear_searcher_tabs()
        self.username_searcher.is_searching = True
        self.search_button.configure(text="⏹ Stop", command=self.stop_username_search)
        self.search_entry.configure(state="disabled")
        self.search_progress_bar.set(0)
        self.status_label.configure(text="🔍 Searching...", text_color="green")
        
        search_thread = threading.Thread(target=self.perform_username_search, args=(username,))
        search_thread.daemon = True
        search_thread.start()
    
    def perform_username_search(self, username: str):
        try:
            def progress_callback(platform, current, total):
                self.window.after(0, self.update_search_progress, platform, current, total)
            results = self.username_searcher.search_all(username, progress_callback)
            if self.username_searcher.is_searching:
                self.window.after(0, self.update_search_results, results, username)
        except Exception as e:
            self.window.after(0, self.show_search_error, str(e))
        finally:
            self.window.after(0, self.search_complete)
    
    def update_search_progress(self, platform: str, current: int, total: int):
        progress = current / total
        self.search_progress_bar.set(progress)
        self.search_progress_label.configure(text=f"Searching {platform}... ({current}/{total})")
    
    def update_search_results(self, results: Dict, username: str):
        self.update_found_tab(results)
        self.update_not_found_tab(results)
        self.update_all_results_tab(results, username)
        
        found_count = sum(1 for data in results.values() if data.get('exists', False))
        total_count = len(results)
        self.status_label.configure(text=f"✓ Search complete - Found {found_count}/{total_count} accounts", text_color="green")
        self.timestamp_label.configure(text=datetime.now().strftime("%H:%M:%S"))
    
    def update_found_tab(self, results: Dict):
        for widget in self.found_scroll.winfo_children():
            widget.destroy()
        
        found_accounts = [(platform, data['url']) for platform, data in results.items() if data.get('exists', False)]
        if not found_accounts:
            ctk.CTkLabel(self.found_scroll, text="No accounts found", font=ctk.CTkFont(size=14)).pack(pady=20)
            return
        
        for platform, url in found_accounts:
            platform_info = self.username_searcher.platforms.get(platform, {})
            item_frame = ctk.CTkFrame(self.found_scroll)
            item_frame.pack(fill="x", padx=10, pady=2)
            
            platform_label = ctk.CTkLabel(item_frame, text=f"{platform_info.get('icon', '')} {platform}", font=ctk.CTkFont(size=12), width=150, anchor="w")
            platform_label.pack(side="left", padx=(10, 0))
            
            url_button = ctk.CTkButton(item_frame, text=url, fg_color="transparent", hover_color=platform_info.get('color', '#2b2b2b'), text_color="#2ecc71", anchor="w", command=lambda u=url: webbrowser.open(u))
            url_button.pack(side="left", fill="x", expand=True, padx=10)
    
    def update_not_found_tab(self, results: Dict):
        for widget in self.not_found_scroll.winfo_children():
            widget.destroy()
        
        not_found = [platform for platform, data in results.items() if not data.get('exists', False)]
        if not not_found:
            ctk.CTkLabel(self.not_found_scroll, text="All accounts found! 🎉", font=ctk.CTkFont(size=14)).pack(pady=20)
            return
        
        for platform in not_found:
            platform_info = self.username_searcher.platforms.get(platform, {})
            item_frame = ctk.CTkFrame(self.not_found_scroll)
            item_frame.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(item_frame, text=f"{platform_info.get('icon', '')} {platform}", font=ctk.CTkFont(size=12), anchor="w").pack(side="left", padx=10)
    
    def update_all_results_tab(self, results: Dict, username: str):
        self.all_results_text.delete("1.0", "end")
        self.all_results_text.insert("1.0", f"Search Results for '{username}'\n{'='*50}\n\n")
        
        found_count = sum(1 for data in results.values() if data.get('exists', False))
        total_count = len(results)
        self.all_results_text.insert("end", f"Summary: Found {found_count}/{total_count} accounts\n\n")
        
        found = [(platform, data) for platform, data in results.items() if data.get('exists', False)]
        if found:
            self.all_results_text.insert("end", "✅ ACCOUNTS FOUND:\n" + "-" * 30 + "\n")
            for platform, data in found:
                self.all_results_text.insert("end", f"{platform}\n  URL: {data['url']}\n\n")
        
        not_found = [(platform, data) for platform, data in results.items() if not data.get('exists', False)]
        if not_found:
            self.all_results_text.insert("end", "\n❌ ACCOUNTS NOT FOUND:\n" + "-" * 30 + "\n")
            for platform, data in not_found:
                self.all_results_text.insert("end", f"{platform}\n\n")
    
    def clear_searcher_tabs(self):
        for widget in self.found_scroll.winfo_children():
            widget.destroy()
        for widget in self.not_found_scroll.winfo_children():
            widget.destroy()
        self.all_results_text.delete("1.0", "end")
    
    def show_search_error(self, error_message: str):
        self.status_label.configure(text=f"⚠ Error: {error_message}", text_color="red")
    
    def search_complete(self):
        self.username_searcher.is_searching = False
        self.search_button.configure(text="🔍 Search", command=self.start_username_search)
        self.search_entry.configure(state="normal")
        self.search_progress_label.configure(text="Search complete")
    
    def stop_username_search(self):
        self.username_searcher.is_searching = False
        self.status_label.configure(text="⏹ Search stopped by user", text_color="orange")
    
    # ==================== Availability Checker Methods ====================
    def setup_availability_tab(self):
        input_frame = ctk.CTkFrame(self.availability_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.avail_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter username to check availability...", font=ctk.CTkFont(size=14), height=45)
        self.avail_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.avail_entry.bind("<Return>", lambda e: self.start_availability_check())
        
        self.avail_button = ctk.CTkButton(input_frame, text="✅ Check Availability", command=self.start_availability_check, height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.avail_button.pack(side="right")
        
        progress_frame = ctk.CTkFrame(self.availability_tab)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        self.avail_progress_label = ctk.CTkLabel(progress_frame, text="Ready to check", font=ctk.CTkFont(size=12))
        self.avail_progress_label.pack()
        
        self.avail_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.avail_progress_bar.pack(fill="x", pady=(5, 0))
        self.avail_progress_bar.set(0)
        
        results_frame = ctk.CTkFrame(self.availability_tab)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        tree_frame = tk.Frame(results_frame, bg=self.bg_color)
        tree_frame.pack(fill="both", expand=True)
        
        self.avail_tree = ttk.Treeview(tree_frame, columns=('platform', 'status', 'details'), show='headings', height=20)
        self.avail_tree.heading('platform', text='Platform')
        self.avail_tree.heading('status', text='Status')
        self.avail_tree.heading('details', text='Details')
        self.avail_tree.column('platform', width=150)
        self.avail_tree.column('status', width=120, anchor='center')
        self.avail_tree.column('details', width=500)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.avail_tree.yview)
        self.avail_tree.configure(yscrollcommand=scrollbar.set)
        self.avail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.avail_tree.tag_configure('available', foreground='#4caf50')
        self.avail_tree.tag_configure('taken', foreground='#f44336')
        self.avail_tree.tag_configure('error', foreground='#ff9800')
    
    def start_availability_check(self):
        username = self.avail_entry.get().strip()
        if not username:
            self.status_label.configure(text="⚠ Please enter a username", text_color="orange")
            return
        if len(username) < 3:
            self.status_label.configure(text="⚠ Username should be at least 3 characters", text_color="orange")
            return
        
        self.avail_button.configure(text="⏹ Checking...", state="disabled")
        self.avail_entry.configure(state="disabled")
        self.avail_progress_bar.set(0)
        self.status_label.configure(text=f"🔍 Checking username: {username}...", text_color="green")
        
        for item in self.avail_tree.get_children():
            self.avail_tree.delete(item)
        
        check_thread = threading.Thread(target=self.perform_availability_check, args=(username,))
        check_thread.daemon = True
        check_thread.start()
    
    def perform_availability_check(self, username: str):
        try:
            def progress_callback(platform, status, current, total):
                progress = current / total
                self.window.after(0, self.avail_progress_bar.set, progress)
                if status == "checking":
                    self.window.after(0, self.avail_progress_label.configure, {"text": f"Checking {platform}... ({current}/{total})"})
                elif current == total:
                    self.window.after(0, self.avail_progress_label.configure, {"text": "Check completed!"})
            
            results = self.availability_checker.check_username(username, progress_callback)
            self.window.after(0, self.display_availability_results, results)
            self.window.after(0, self.status_label.configure, {"text": f"✓ Check completed for @{username}", "text_color": "green"})
        except Exception as e:
            self.window.after(0, self.status_label.configure, {"text": f"⚠ Error: {str(e)}", "text_color": "red"})
        finally:
            self.window.after(0, self.availability_check_complete)
    
    def display_availability_results(self, results: Dict):
        for platform, (is_available, message) in results.items():
            status_text = "✓ AVAILABLE" if is_available else "✗ TAKEN"
            tag = 'available' if is_available else 'taken'
            if "Error" in message or "Could not verify" in message:
                tag = 'error'
            self.avail_tree.insert('', tk.END, values=(platform, status_text, message), tags=(tag,))
    
    def availability_check_complete(self):
        self.avail_button.configure(text="✅ Check Availability", command=self.start_availability_check, state="normal")
        self.avail_entry.configure(state="normal")
    
    # ==================== Discord Exporter Methods ====================
    def setup_exporter_tab(self):
        token_frame = ctk.CTkFrame(self.exporter_tab)
        token_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        ctk.CTkLabel(token_frame, text="Discord Token:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=5, pady=(5, 0))
        
        token_row = ctk.CTkFrame(token_frame)
        token_row.pack(fill="x", padx=5, pady=5)
        
        self.exporter_token_entry = ctk.CTkEntry(token_row, placeholder_text="Enter Discord token...", show="*", height=35)
        self.exporter_token_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.token_show_btn = ctk.CTkButton(token_row, text="👁", width=40, command=self.toggle_token_visibility)
        self.token_show_btn.pack(side="right", padx=2)
        
        self.token_help_btn = ctk.CTkButton(token_row, text="?", width=40, command=self.show_token_help)
        self.token_help_btn.pack(side="right")
        
        self.save_token_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(token_frame, text="Save token", variable=self.save_token_var).pack(anchor="w", padx=5, pady=2)
        
        channel_frame = ctk.CTkFrame(self.exporter_tab)
        channel_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(channel_frame, text="Channel Settings:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=5, pady=(5, 0))
        
        channel_row = ctk.CTkFrame(channel_frame)
        channel_row.pack(fill="x", padx=5, pady=5)
        
        self.channel_id_entry = ctk.CTkEntry(channel_row, placeholder_text="Channel ID...", height=35)
        self.channel_id_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.channel_help_btn = ctk.CTkButton(channel_row, text="?", width=40, command=self.show_channel_help)
        self.channel_help_btn.pack(side="right")
        
        limit_row = ctk.CTkFrame(channel_frame)
        limit_row.pack(fill="x", padx=5, pady=5)
        
        self.message_limit_entry = ctk.CTkEntry(limit_row, placeholder_text="Message limit (empty = all)", height=35)
        self.message_limit_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        format_frame = ctk.CTkFrame(self.exporter_tab)
        format_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(format_frame, text="Export Format:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=5, pady=(5, 0))
        
        format_row = ctk.CTkFrame(format_frame)
        format_row.pack(fill="x", padx=5, pady=5)
        
        self.export_format_var = tk.StringVar(value="all")
        for text, value in [("JSON", "json"), ("CSV", "csv"), ("HTML", "html"), ("TXT", "txt"), ("ALL", "all")]:
            ctk.CTkRadioButton(format_row, text=text, variable=self.export_format_var, value=value).pack(side="left", padx=5)
        
        options_frame = ctk.CTkFrame(self.exporter_tab)
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.include_reactions_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(options_frame, text="Include Reactions", variable=self.include_reactions_var).pack(side="left", padx=5)
        
        progress_frame = ctk.CTkFrame(self.exporter_tab)
        progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.exporter_progress_label = ctk.CTkLabel(progress_frame, text="Ready", font=ctk.CTkFont(size=12))
        self.exporter_progress_label.pack()
        
        self.exporter_progress_bar = ctk.CTkProgressBar(progress_frame)
        self.exporter_progress_bar.pack(fill="x", pady=(5, 0))
        self.exporter_progress_bar.set(0)
        
        self.exporter_status_label = ctk.CTkLabel(progress_frame, text="", font=ctk.CTkFont(size=11), text_color="#888888")
        self.exporter_status_label.pack()
        
        log_frame = ctk.CTkFrame(self.exporter_tab)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ctk.CTkLabel(log_frame, text="Log:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=5, pady=(5, 0))
        
        self.exporter_log_text = ctk.CTkTextbox(log_frame, font=ctk.CTkFont(size=11))
        self.exporter_log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        button_frame = ctk.CTkFrame(self.exporter_tab)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        self.export_button = ctk.CTkButton(button_frame, text="▶ START EXPORT", command=self.start_discord_export, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        self.export_button.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.clear_log_btn = ctk.CTkButton(button_frame, text="🗑 CLEAR LOG", command=self.clear_export_log, height=40)
        self.clear_log_btn.pack(side="left", fill="x", expand=True, padx=2)
        
        self.clear_token_btn = ctk.CTkButton(button_frame, text="🔑 CLEAR TOKEN", command=self.clear_saved_token, height=40)
        self.clear_token_btn.pack(side="left", fill="x", expand=True, padx=2)
        
        self.open_folder_btn = ctk.CTkButton(button_frame, text="📁 OPEN FOLDER", command=self.open_export_folder, height=40)
        self.open_folder_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        self.load_saved_token()
    
    def toggle_token_visibility(self):
        if self.exporter_token_entry.cget('show') == '*':
            self.exporter_token_entry.configure(show='')
        else:
            self.exporter_token_entry.configure(show='*')
    
    def show_token_help(self):
        messagebox.showinfo("Get Token", "Get Discord Token:\n\n1. Open Discord in browser (F12)\n2. Network tab → Refresh\n3. Click any request\n4. Copy 'authorization' header value")
    
    def show_channel_help(self):
        messagebox.showinfo("Get Channel ID", "Get Channel ID:\n\nEnable Developer Mode in Discord:\nSettings → Advanced → Developer Mode\n\nRight-click channel → Copy ID")
    
    def load_saved_token(self):
        saved_token = self.discord_exporter.token_storage.load_token()
        if saved_token:
            self.exporter_token_entry.delete(0, tk.END)
            self.exporter_token_entry.insert(0, saved_token)
            self.log_export_message("Loaded saved token")
    
    def clear_saved_token(self):
        if messagebox.askyesno("Confirm", "Clear saved token?"):
            self.discord_exporter.token_storage.clear_token()
            self.exporter_token_entry.delete(0, tk.END)
            self.log_export_message("Saved token cleared")
    
    def open_export_folder(self):
        export_dir = Path("discord_exports")
        if export_dir.exists():
            if sys.platform == 'win32':
                os.startfile(export_dir)
            else:
                os.system(f'open "{export_dir}"' if sys.platform == 'darwin' else f'xdg-open "{export_dir}"')
        else:
            messagebox.showinfo("No Exports", "Export some chats first!")
    
    def log_export_message(self, message, tag='info'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.exporter_log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.exporter_log_text.see(tk.END)
    
    def clear_export_log(self):
        self.exporter_log_text.delete("1.0", tk.END)
    
    def update_export_progress(self, current, total, status=""):
        if total > 0:
            percent = (current / total) * 100
            self.exporter_progress_bar.set(percent / 100)
            self.exporter_progress_label.configure(text=f"{current}/{total} ({percent:.0f}%)")
            if status:
                self.exporter_status_label.configure(text=status)
        if current == total:
            self.exporter_status_label.configure(text="✓ Complete!")
    
    def perform_discord_export(self):
        token = self.exporter_token_entry.get().strip()
        channel_id = self.channel_id_entry.get().strip()
        message_limit = self.message_limit_entry.get().strip()
        export_format = self.export_format_var.get()
        include_reactions = self.include_reactions_var.get()
        
        def progress_callback(current, total, status):
            self.window.after(0, self.update_export_progress, current, total, status)
        
        def log_callback(message, tag):
            self.window.after(0, self.log_export_message, message, tag)
        
        if self.save_token_var.get() and token:
            self.discord_exporter.token_storage.save_token(token)
        
        self.discord_exporter.export(token, channel_id, message_limit, export_format, include_reactions, progress_callback, log_callback)
        self.window.after(0, self.export_complete)
    
    def export_complete(self):
        self.export_button.configure(text="▶ START EXPORT", command=self.start_discord_export, state="normal")
        self.exporter_progress_label.configure(text="Export complete")
    
    def start_discord_export(self):
        token = self.exporter_token_entry.get().strip()
        channel_id = self.channel_id_entry.get().strip()
        
        if not token:
            messagebox.showerror("Error", "Enter Discord token")
            return
        if not channel_id:
            messagebox.showerror("Error", "Enter channel ID")
            return
        
        self.export_button.configure(text="⏹ Exporting...", state="disabled")
        self.exporter_progress_bar.set(0)
        self.exporter_progress_label.configure(text="Starting...")
        self.exporter_status_label.configure(text="")
        
        export_thread = threading.Thread(target=self.perform_discord_export)
        export_thread.daemon = True
        export_thread.start()
    
    def run(self):
        self.window.mainloop()


def main():
    try:
        from cryptography.fernet import Fernet
        import dns.resolver
        import phonenumbers
        import whois
        from email_validator import validate_email
        import qrcode
        from PIL import Image, ImageTk
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "dnspython", "phonenumbers", "python-whois", "email-validator", "qrcode", "pillow"])
    
    app = CombinedApp()
    app.run()


if __name__ == "__main__":
    main()