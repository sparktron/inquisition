# inquisition

A website fingerprinting tool that identifies technologies, frameworks, and services running on web targets.

## Features

- Detect web frameworks, CMS platforms, and JavaScript libraries
- Identify server software and version information
- Enumerate HTTP headers and security configurations
- Check for common web technologies via response analysis
- Output results in plain text or JSON format

## Requirements

- Python 3.8+
- pip

## Installation

### From source

```bash
git clone https://github.com/sparktron/inquisition.git
cd inquisition
pip install -r requirements.txt
```

### Using pip

```bash
pip install inquisition
```

## Usage

### Basic scan

```bash
python inquisition.py <target-url>
```

Example:

```bash
python inquisition.py https://example.com
```

### Options

```
usage: inquisition.py [-h] [-o {text,json}] [-t TIMEOUT] [-v] url

positional arguments:
  url                   Target URL to fingerprint

options:
  -h, --help            Show this help message and exit
  -o {text,json}        Output format (default: text)
  -t TIMEOUT            Request timeout in seconds (default: 10)
  -v, --verbose         Enable verbose output
```

### Examples

Scan a target and output results as JSON:

```bash
python inquisition.py https://example.com -o json
```

Scan with verbose output and a custom timeout:

```bash
python inquisition.py https://example.com -v -t 30
```

Save results to a file:

```bash
python inquisition.py https://example.com -o json > results.json
```

## Example Output

```
Target: https://example.com
─────────────────────────────
Server:       nginx/1.24.0
Framework:    WordPress 6.4
Language:     PHP
JavaScript:   jQuery 3.6.0
CDN:          Cloudflare
Headers:
  X-Powered-By: PHP/8.1.0
  Content-Security-Policy: detected
```

## Legal

Only use this tool against targets you own or have explicit permission to test. Unauthorized scanning may violate computer fraud laws.

## License

MIT
