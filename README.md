# Raze-Interview-IP-Threat-Checker

A Python-based IP reputation checker that queries multiple threat intelligence feeds to assess IP address trustworthiness and security risk. Built for CTI (Cyber Threat Intelligence) teams.

##  Purpose

This tool was created as a part of the **Raze CyberSecurity Interview Task (Question 6)** to demonstrate practical threat intelligence aggregation and IP reputation analysis capabilities.

##  Features

### Multi-Source Intelligence
Aggregates data from 5 leading threat intelligence feeds:
- **AbuseIPDB** - Community-driven abuse reporting database
- **VirusTotal** - Multi-vendor malware and URL scanning
- **AlienVault OTX** - Open Threat Exchange platform
- **Shodan** - Internet-connected device search engine
- **GreyNoise** - Internet noise and scanner classification

### Core Capabilities
- **Automated Risk Scoring** - Calculates risk percentage and confidence levels
- **Batch Processing** - Check single or multiple IPs simultaneously
- **Interactive CLI** - Easily usable command-line interface
- **JSON Export** - Detailed reports saved for further analysis
- **Robust Error Handling** - Graceful handling of timeouts and API failures
- **IP Validation** - Automatic validation of IP address format

### Prerequisites
- Python 3.7 or higher
- pip package manager
- Internet connection

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Elina0604/Raze-Interview-IP-Threat-Checker.git
cd Raze-Interview-IP-Threat-Checker
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Obtain API keys** (free tiers available):
   - [AbuseIPDB](https://www.abuseipdb.com/api) 
   - [VirusTotal](https://www.virustotal.com/gui/join-us) 
   - [Shodan](https://account.shodan.io/register) 
   - [GreyNoise](https://www.greynoise.io/) 

**Note:** AlienVault OTX does not require an API key.

## Usage

### Running the Tool

```bash
python ip_checker.py
```

### Step-by-Step Workflow

**1. API Key Setup** (first-time only):
```
Enter AbuseIPDB API key (or press Enter to skip): your_key_here
Enter VirusTotal API key (or press Enter to skip): your_key_here
Enter Shodan API key (or press Enter to skip): your_key_here
Enter GreyNoise API key (or press Enter to skip): your_key_here

API keys configured!
```

**2. Enter an IP Address:**
```
Enter IP address(es): 8.8.8.8
```

Or check multiple IPs:
```
Enter IP address(es): 8.8.8.8, 1.1.1.1, 9.9.9.9
```

**3. Review Results:**
```
============================================================
THREAT INTELLIGENCE REPORT
============================================================

IP ADDRESS: 8.8.8.8
ANALYZED: 2025-12-02T23:14:51

────────────────────────────────────────────────────────────
RISK ASSESSMENT
────────────────────────────────────────────────────────────
Risk Level: CLEAN
Risk Score: 0.0%
Confidence: HIGH
Detections: 0/5 feeds

RECOMMENDATION:
NO ACTION REQUIRED - No malicious indicators found across threat feeds.

────────────────────────────────────────────────────────────
DETAILED RESULTS
────────────────────────────────────────────────────────────

[AbuseIPDB]
  is_malicious: False
  confidence_score: 0
  total_reports: 160
  country: US
  isp: Google LLC
  ...
```

##  Risk Assessment Matrix

The tool calculates risk based on the percentage of feeds that flag an IP as malicious:

| Risk Level | Score Range | Detections | Action Required |
|------------|-------------|------------|-----------------|
| **CRITICAL** | 75-100% | 4-5 feeds | Block immediately - High confidence threat |
| **HIGH** | 50-74% | 3 feeds | Block recommended - Multiple sources flagged |
| **MEDIUM** | 25-49% | 2 feeds | Monitor closely - Some indicators present |
| **LOW** | 1-24% | 1 feed | Investigate - Limited threat indicators |
| **CLEAN** | 0% | 0 feeds | No action required - No malicious indicators |

##  Output Files

The tool generates timestamped JSON reports in the current directory:

```
ip_analysis_8_8_8_8_20251202_231451.json
```

### Report Contents:
- Individual feed results
- Risk assessment metrics
- Geolocation data
- ISP/Organization information
- Open ports (via Shodan)
- Vulnerability data (if applicable)
- Abuse confidence scores
- Historical reporting data

## Security Best Practices

### API Key Management
-  **Never commit API keys** to version control
-  Use environment variables for production deployments
-  Rotate API keys regularly
-  Review `.gitignore` to ensure sensitive files are excluded

## Dependencies
 
requests - HTTP library for API calls
Standard Python libraries (json, datetime, time, typing)

## Known Issues & Limitations

AlienVault OTX may occasionally timeout on slow connections (20s timeout configured)
Free API tiers have rate limits - see individual provider documentation
Large batch checks may take time due to rate limiting delays

## API Documentation
For detailed API documentation, refer to:

AbuseIPDB API Docs
VirusTotal API Docs
AlienVault OTX API Docs
Shodan API Docs
GreyNoise API Docs

## Contributing
This is a private repository for the Raze CyberSecurity Interview Task.
## License
This project is for interview demonstration purposes.

## Acknowledgments
AbuseIPDB, VirusTotal, AlienVault, Shodan, and GreyNoise for providing threat intelligence APIs
Raze CyberSecurity for the interview opportunity
The open-source community for security tools and best practices
