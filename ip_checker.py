#!/usr/bin/env python3
"""
IP Threat Intelligence Aggregator
Checks multiple threat intelligence feeds for IP reputation
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Any
import time

class IPThreatIntel:
    def __init__(self, api_keys: Dict[str, str] = None):
        """
        Initialize with API keys for various services
        api_keys: dict with keys like 'virustotal', 'abuseipdb', 'shodan', etc.
        """
        self.api_keys = api_keys or {}
        self.results = {}
        
    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check AbuseIPDB for IP reputation"""
        if 'abuseipdb' not in self.api_keys:
            return {"error": "API key not provided"}
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_keys['abuseipdb']
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "source": "AbuseIPDB",
                    "is_malicious": data.get('abuseConfidenceScore', 0) > 50,
                    "confidence_score": data.get('abuseConfidenceScore', 0),
                    "total_reports": data.get('totalReports', 0),
                    "country": data.get('countryCode', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "usage_type": data.get('usageType', 'Unknown'),
                    "is_whitelisted": data.get('isWhitelisted', False),
                    "last_reported": data.get('lastReportedAt', 'Never')
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.Timeout:
            return {"error": "Connection timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_virustotal(self, ip: str) -> Dict[str, Any]:
        """Check VirusTotal for IP reputation"""
        if 'virustotal' not in self.api_keys:
            return {"error": "API key not provided"}
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": self.api_keys['virustotal']
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    "source": "VirusTotal",
                    "is_malicious": last_analysis.get('malicious', 0) > 0,
                    "malicious_detections": last_analysis.get('malicious', 0),
                    "suspicious_detections": last_analysis.get('suspicious', 0),
                    "clean_detections": last_analysis.get('harmless', 0),
                    "total_vendors": sum(last_analysis.values()),
                    "country": data.get('country', 'Unknown'),
                    "as_owner": data.get('as_owner', 'Unknown'),
                    "reputation": data.get('reputation', 0)
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.Timeout:
            return {"error": "Connection timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_alienvault_otx(self, ip: str) -> Dict[str, Any]:
        """Check AlienVault OTX for IP reputation (No API key required for basic queries)"""
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        
        try:
            response = requests.get(url, timeout=20)  # Increased timeout
            if response.status_code == 200:
                data = response.json()
                
                # Get reputation URL with retry logic
                reputation_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
                try:
                    rep_response = requests.get(reputation_url, timeout=20)
                    reputation = rep_response.json() if rep_response.status_code == 200 else {}
                except:
                    reputation = {}  # Skip reputation if it times out
                
                return {
                    "source": "AlienVault OTX",
                    "is_malicious": data.get('pulse_info', {}).get('count', 0) > 0,
                    "pulse_count": data.get('pulse_info', {}).get('count', 0),
                    "reputation_score": reputation.get('reputation', 0),
                    "country": data.get('country_name', 'Unknown'),
                    "asn": data.get('asn', 'Unknown')
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.Timeout:
            return {"error": "Connection timed out - service may be slow or unreachable"}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed - check your internet connection"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def check_shodan(self, ip: str) -> Dict[str, Any]:
        """Check Shodan for IP information"""
        if 'shodan' not in self.api_keys:
            return {"error": "API key not provided"}
        
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.api_keys['shodan']}
        
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "source": "Shodan",
                    "open_ports": data.get('ports', []),
                    "vulnerabilities": data.get('vulns', []),
                    "has_vulnerabilities": len(data.get('vulns', [])) > 0,
                    "country": data.get('country_name', 'Unknown'),
                    "organization": data.get('org', 'Unknown'),
                    "hostnames": data.get('hostnames', []),
                    "tags": data.get('tags', [])
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_greynoise(self, ip: str) -> Dict[str, Any]:
        """Check GreyNoise for IP classification"""
        if 'greynoise' not in self.api_keys:
            return {"error": "API key not provided"}
        
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            "key": self.api_keys['greynoise']
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "source": "GreyNoise",
                    "is_malicious": data.get('classification') == 'malicious',
                    "classification": data.get('classification', 'unknown'),
                    "name": data.get('name', 'Unknown'),
                    "last_seen": data.get('last_seen', 'Never'),
                    "noise": data.get('noise', False)
                }
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def check_threatfox(self, ip: str) -> Dict[str, Any]:
        """Check ThreatFox (abuse.ch) for IOC data"""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "query": "search_ioc",
            "search_term": ip
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('query_status') == 'ok':
                    ioc_data = data.get('data', [])
                    return {
                        "source": "ThreatFox",
                        "is_malicious": len(ioc_data) > 0,
                        "ioc_count": len(ioc_data),
                        "threat_types": list(set([ioc.get('threat_type', '') for ioc in ioc_data])),
                        "malware_families": list(set([ioc.get('malware', '') for ioc in ioc_data]))
                    }
                elif data.get('query_status') == 'no_result':
                    return {
                        "source": "ThreatFox",
                        "is_malicious": False,
                        "ioc_count": 0,
                        "message": "No threats found"
                    }
                else:
                    return {"error": f"Query status: {data.get('query_status', 'unknown')}"}
            else:
                return {"error": f"HTTP {response.status_code}"}
        except requests.exceptions.Timeout:
            return {"error": "Connection timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """
        Analyze IP across all available threat intelligence feeds
        """
        print(f"\n{'='*60}")
        print(f"Analyzing IP: {ip}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Run all checks
        checks = [
            ("AbuseIPDB", self.check_abuseipdb),
            ("VirusTotal", self.check_virustotal),
            ("AlienVault OTX", self.check_alienvault_otx),
            ("Shodan", self.check_shodan),
            ("GreyNoise", self.check_greynoise)
        ]
        
        results = {}
        for name, check_func in checks:
            print(f"Checking {name}...", end=" ")
            result = check_func(ip)
            results[name] = result
            
            if "error" in result:
                print(f"WARNING: {result['error']}")
            else:
                is_malicious = result.get('is_malicious', False)
                print(f"{'[MALICIOUS]' if is_malicious else '[Clean]'}")
            
            time.sleep(0.5)  # Rate limiting
        
        # Calculate overall risk score
        risk_assessment = self.calculate_risk_score(results)
        
        return {
            "ip_address": ip,
            "timestamp": datetime.now().isoformat(),
            "individual_results": results,
            "risk_assessment": risk_assessment
        }
    
    def calculate_risk_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score from all feeds"""
        malicious_count = 0
        total_feeds = 0
        risk_factors = []
        
        for feed_name, data in results.items():
            if "error" not in data:
                total_feeds += 1
                if data.get('is_malicious', False):
                    malicious_count += 1
                    risk_factors.append(feed_name)
        
        if total_feeds == 0:
            return {
                "risk_level": "UNKNOWN",
                "risk_score": 0,
                "confidence": "LOW"
            }
        
        risk_percentage = (malicious_count / total_feeds) * 100
        
        if risk_percentage >= 75:
            risk_level = "CRITICAL"
            confidence = "HIGH"
        elif risk_percentage >= 50:
            risk_level = "HIGH"
            confidence = "MEDIUM"
        elif risk_percentage >= 25:
            risk_level = "MEDIUM"
            confidence = "MEDIUM"
        elif risk_percentage > 0:
            risk_level = "LOW"
            confidence = "LOW"
        else:
            risk_level = "CLEAN"
            confidence = "HIGH"
        
        return {
            "risk_level": risk_level,
            "risk_score": round(risk_percentage, 2),
            "malicious_detections": malicious_count,
            "total_feeds_checked": total_feeds,
            "flagged_by": risk_factors,
            "confidence": confidence,
            "recommendation": self.get_recommendation(risk_level)
        }
    
    def get_recommendation(self, risk_level: str) -> str:
        """Provide actionable recommendations based on risk level"""
        recommendations = {
            "CRITICAL": "BLOCK IMMEDIATELY - High confidence threat. Implement firewall rules and investigate any connections.",
            "HIGH": "BLOCK RECOMMENDED - Multiple sources flag as malicious. Monitor and investigate.",
            "MEDIUM": "MONITOR CLOSELY - Some indicators of malicious activity. Enhanced logging recommended.",
            "LOW": "INVESTIGATE - Limited threat indicators. Review context before action.",
            "CLEAN": "NO ACTION REQUIRED - No malicious indicators found across threat feeds."
        }
        return recommendations.get(risk_level, "Review manually")
    
    def print_report(self, analysis: Dict[str, Any]):
        """Print a formatted report"""
        print(f"\n{'='*60}")
        print("THREAT INTELLIGENCE REPORT")
        print(f"{'='*60}")
        
        risk = analysis['risk_assessment']
        
        print(f"\nIP ADDRESS: {analysis['ip_address']}")
        print(f"ANALYZED: {analysis['timestamp']}")
        print(f"\n{'─'*60}")
        print(f"\nRISK ASSESSMENT")
        print(f"{'─'*60}")
        print(f"Risk Level: {risk['risk_level']}")
        print(f"Risk Score: {risk['risk_score']}%")
        print(f"Confidence: {risk['confidence']}")
        print(f"Detections: {risk['malicious_detections']}/{risk['total_feeds_checked']} feeds")
        
        if risk['flagged_by']:
            print(f"Flagged by: {', '.join(risk['flagged_by'])}")
        
        print(f"\nRECOMMENDATION:")
        print(f"{risk['recommendation']}")
        
        print(f"\n{'─'*60}")
        print("DETAILED RESULTS")
        print(f"{'─'*60}")
        
        for feed_name, data in analysis['individual_results'].items():
            print(f"\n[{feed_name}]")
            if "error" in data:
                print(f"  Error: {data['error']}")
            else:
                for key, value in data.items():
                    if key != 'source':
                        print(f"  {key}: {value}")
        
        print(f"\n{'='*60}\n")


# Example usage
if __name__ == "__main__":
    print("=" * 60)
    print("IP THREAT INTELLIGENCE CHECKER")
    print("=" * 60)
    print("\nThis tool checks IP addresses against multiple threat feeds.")
    print("You can check single or multiple IPs.\n")
    
    # Configure API keys (replace with your actual keys)
    print("Configuring API keys...")
    api_keys = {}
    
    # Ask user for API keys
    print("\n--- API KEY SETUP ---")
    print("Press Enter to skip optional services\n")
    
    abuseipdb_key = input("Enter AbuseIPDB API key (or press Enter to skip): ").strip()
    if abuseipdb_key:
        api_keys['abuseipdb'] = abuseipdb_key
    
    virustotal_key = input("Enter VirusTotal API key (or press Enter to skip): ").strip()
    if virustotal_key:
        api_keys['virustotal'] = virustotal_key
    
    shodan_key = input("Enter Shodan API key (or press Enter to skip): ").strip()
    if shodan_key:
        api_keys['shodan'] = shodan_key
    
    greynoise_key = input("Enter GreyNoise API key (or press Enter to skip): ").strip()
    if greynoise_key:
        api_keys['greynoise'] = greynoise_key
    
    print("\nOK - API keys configured!")
    print("Note: AlienVault OTX doesn't require an API key.\n")
    
    # Initialize the checker
    checker = IPThreatIntel(api_keys)
    
    while True:
        print("\n" + "=" * 60)
        print("ENTER IP ADDRESS(ES) TO CHECK")
        print("=" * 60)
        print("\nOptions:")
        print("  - Enter single IP: 8.8.8.8")
        print("  - Enter multiple IPs separated by commas: 8.8.8.8, 1.1.1.1")
        print("  - Type 'quit' or 'exit' to stop\n")
        
        user_input = input("Enter IP address(es): ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("\nThank you for using IP Threat Checker!")
            break
        
        if not user_input:
            print("WARNING: Please enter at least one IP address.")
            continue
        
        # Parse input - handle single or multiple IPs
        ip_list = [ip.strip() for ip in user_input.split(',')]
        
        # Validate IPs
        valid_ips = []
        for ip in ip_list:
            # Basic IP validation
            parts = ip.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
            else:
                print(f"WARNING: Invalid IP format: {ip} (skipping)")
        
        if not valid_ips:
            print("WARNING: No valid IP addresses to check.")
            continue
        
        # Analyze each IP
        for i, ip in enumerate(valid_ips, 1):
            if len(valid_ips) > 1:
                print(f"\n{'#' * 60}")
                print(f"# IP {i} of {len(valid_ips)}")
                print(f"{'#' * 60}")
            
            analysis = checker.analyze_ip(ip)
            checker.print_report(analysis)
            
            # Save to JSON
            filename = f"ip_analysis_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(analysis, f, indent=2)
            print(f"Report saved to: {filename}")
            
            # Small delay between multiple IP checks
            if i < len(valid_ips):
                print("\nMoving to next IP in 2 seconds...")
                time.sleep(2)
        
        # Ask if user wants to check more IPs
        print("\n" + "-" * 60)
        check_more = input("Check more IPs? (yes/no): ").strip().lower()
        if check_more not in ['yes', 'y']:
            print("\nThank you for using IP Threat Checker!")
            break