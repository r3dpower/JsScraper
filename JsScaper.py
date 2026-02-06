#!/usr/bin/env python3
"""
JavaScript File Downloader
Downloads all .js files from a given domain, handling both absolute and relative URLs.
"""

import argparse
import os
import re
import sys
import json
from urllib.parse import urljoin, urlparse, unquote
from pathlib import Path
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install requests beautifulsoup4")
    sys.exit(1)


# Common API key and token patterns
SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
    'GitHub Token': r'gh[pousr]_[0-9a-zA-Z]{36}',
    'GitHub Classic Token': r'ghp_[0-9a-zA-Z]{36}',
    'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
    'GitHub App Token': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth': r'ya29\.[0-9A-Za-z\-_]+',
    'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Restricted Key': r'rk_live_[0-9a-zA-Z]{24}',
    'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
    'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
    'Twilio API Key': r'SK[0-9a-fA-F]{32}',
    'Twitter Access Token': r'[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'Twitter OAuth': r'[tT][wW][iI][tT][tT][eE][rR].*[\'"][0-9a-zA-Z]{35,44}[\'"]',
    'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Facebook OAuth': r'[fF][aA][cC][eE][bB][oO][oO][kK].*[\'"][0-9a-f]{32}[\'"]',
    'Heroku API Key': r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    'NPM Token': r'npm_[0-9a-zA-Z]{36}',
    'PyPI Token': r'pypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,}',
    'Azure Storage Key': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[0-9a-zA-Z+/=]{88}',
    'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    'Generic API Key': r'[aA][pP][iI]_?[kK][eE][yY].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
    'Generic Secret': r'[sS][eE][cC][rR][eE][tT].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
    'Password in Code': r'[pP][aA][sS][sS][wW][oO][rR][dD].*[\'"][^\'"]{8,}[\'"]',
    'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'Firebase URL': r'.*\.firebaseio\.com',
    'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
    'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
    'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
}


def is_valid_url(url):
    """Check if URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def get_js_files_from_html(html_content, base_url):
    """Extract all JavaScript file URLs from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    js_files = set()
    
    # Find script tags with src attribute
    for script in soup.find_all('script', src=True):
        js_url = script['src']
        # Convert relative URLs to absolute
        absolute_url = urljoin(base_url, js_url)
        if absolute_url.endswith('.js') or '.js?' in absolute_url:
            js_files.add(absolute_url)
    
    # Also search for .js references in the HTML content using regex
    js_pattern = r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
    matches = re.findall(js_pattern, html_content)
    for match in matches:
        absolute_url = urljoin(base_url, match)
        js_files.add(absolute_url)
    
    return js_files


def sanitize_filename(url, base_domain):
    """Create a safe filename from URL."""
    parsed = urlparse(url)
    
    # Remove query parameters for filename
    path = parsed.path
    if '?' in url:
        path = path.split('?')[0]
    
    # Decode URL encoding
    path = unquote(path)
    
    # Remove leading slash and create directory structure
    path = path.lstrip('/')
    
    if not path or path.endswith('/'):
        path += 'index.js'
    
    # Replace any remaining problematic characters
    path = path.replace('../', '').replace('..\\', '')
    
    return path


def download_file(url, output_path, session):
    """Download a file from URL to output_path."""
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(response.content)
        
        return True
    except Exception as e:
        print(f"  Error downloading {url}: {e}")
        return False


def scan_file_for_secrets(file_path):
    """
    Scan a single file for secrets using regex patterns.
    Returns a list of findings.
    """
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get the line content
                lines = content.split('\n')
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ''
                
                # Extract context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ')
                
                findings.append({
                    'file': file_path,
                    'type': secret_type,
                    'match': match.group(),
                    'line': line_num,
                    'line_content': line_content,
                    'context': context
                })
    
    except Exception as e:
        print(f"  Error scanning {file_path}: {e}")
    
    return findings


def scan_directory_for_secrets(directory):
    """
    Scan all .js files in a directory for secrets.
    """
    print(f"\n{'=' * 60}")
    print(f"SCANNING FOR SECRETS IN: {directory}")
    print(f"{'=' * 60}\n")
    
    all_findings = []
    files_scanned = 0
    
    # Find all .js files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                files_scanned += 1
                print(f"Scanning: {file_path}")
                
                findings = scan_file_for_secrets(file_path)
                if findings:
                    all_findings.extend(findings)
                    print(f"  ⚠️  Found {len(findings)} potential secret(s)")
                else:
                    print(f"  ✓ Clean")
    
    # Print summary
    print(f"\n{'=' * 60}")
    print(f"SCAN SUMMARY")
    print(f"{'=' * 60}")
    print(f"Files scanned: {files_scanned}")
    print(f"Potential secrets found: {len(all_findings)}")
    print(f"{'=' * 60}\n")
    
    if all_findings:
        # Group findings by type
        findings_by_type = {}
        for finding in all_findings:
            secret_type = finding['type']
            if secret_type not in findings_by_type:
                findings_by_type[secret_type] = []
            findings_by_type[secret_type].append(finding)
        
        # Print detailed findings
        print(f"DETAILED FINDINGS:")
        print(f"{'=' * 60}\n")
        
        for secret_type, findings in findings_by_type.items():
            print(f"\n🔍 {secret_type} ({len(findings)} found)")
            print("-" * 60)
            
            for i, finding in enumerate(findings, 1):
                print(f"\n  [{i}] File: {finding['file']}")
                print(f"      Line: {finding['line']}")
                print(f"      Match: {finding['match'][:100]}{'...' if len(finding['match']) > 100 else ''}")
                print(f"      Context: ...{finding['context']}...")
        
        # Save to JSON file
        output_file = os.path.join(directory, 'secrets_scan_results.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'scan_date': datetime.now().isoformat(),
                'directory': directory,
                'files_scanned': files_scanned,
                'total_findings': len(all_findings),
                'findings': all_findings,
                'findings_by_type': {k: len(v) for k, v in findings_by_type.items()}
            }, f, indent=2)
        
        print(f"\n{'=' * 60}")
        print(f"⚠️  SECURITY WARNING:")
        print(f"Found {len(all_findings)} potential secrets in {files_scanned} files!")
        print(f"Detailed results saved to: {output_file}")
        print(f"{'=' * 60}\n")
        print("⚡ RECOMMENDATIONS:")
        print("  1. Review each finding carefully (some may be false positives)")
        print("  2. Rotate any exposed credentials immediately")
        print("  3. Never commit secrets to version control")
        print("  4. Use environment variables or secret management tools")
        print("  5. Consider using tools like git-secrets or TruffleHog")
        print(f"{'=' * 60}\n")
    else:
        print("✓ No secrets detected in scanned files.\n")
    
    return all_findings


def crawl_and_download_js(domain, output_dir='downloaded_js', max_pages=50):
    """
    Crawl the domain and download all JavaScript files.
    
    Args:
        domain: The domain to crawl (e.g., 'https://example.com')
        output_dir: Directory to save downloaded files
        max_pages: Maximum number of pages to crawl
    """
    if not is_valid_url(domain):
        if not domain.startswith('http'):
            domain = 'https://' + domain
        if not is_valid_url(domain):
            print(f"Error: Invalid domain: {domain}")
            return
    
    parsed_domain = urlparse(domain)
    base_domain = f"{parsed_domain.scheme}://{parsed_domain.netloc}"
    
    print(f"Starting download from: {domain}")
    print(f"Output directory: {output_dir}")
    print("-" * 60)
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    visited_urls = set()
    pages_to_visit = {domain}
    js_files = set()
    downloaded_count = 0
    
    # Crawl pages to find JS files
    while pages_to_visit and len(visited_urls) < max_pages:
        current_url = pages_to_visit.pop()
        
        if current_url in visited_urls:
            continue
        
        visited_urls.add(current_url)
        print(f"\nCrawling: {current_url}")
        
        try:
            response = session.get(current_url, timeout=30)
            response.raise_for_status()
            
            # Extract JS files from this page
            page_js_files = get_js_files_from_html(response.text, current_url)
            new_js_files = page_js_files - js_files
            js_files.update(new_js_files)
            
            if new_js_files:
                print(f"  Found {len(new_js_files)} new JS file(s)")
            
            # Find more pages to crawl (only from same domain)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(current_url, href)
                parsed = urlparse(absolute_url)
                
                # Only crawl pages from the same domain
                if parsed.netloc == parsed_domain.netloc:
                    # Remove fragment
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if parsed.query:
                        clean_url += f"?{parsed.query}"
                    
                    if clean_url not in visited_urls and len(visited_urls) < max_pages:
                        pages_to_visit.add(clean_url)
        
        except Exception as e:
            print(f"  Error crawling {current_url}: {e}")
    
    print(f"\n{'=' * 60}")
    print(f"Found {len(js_files)} total JavaScript file(s)")
    print(f"{'=' * 60}\n")
    
    # Download all found JS files
    for js_url in js_files:
        filename = sanitize_filename(js_url, base_domain)
        output_path = os.path.join(output_dir, filename)
        
        print(f"Downloading: {js_url}")
        print(f"  -> {output_path}")
        
        if download_file(js_url, output_path, session):
            downloaded_count += 1
            print(f"  ✓ Success")
        else:
            print(f"  ✗ Failed")
    
    print(f"\n{'=' * 60}")
    print(f"Downloaded {downloaded_count}/{len(js_files)} JavaScript files")
    print(f"Files saved to: {os.path.abspath(output_dir)}")
    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description='Download all JavaScript files from a given domain and optionally scan for secrets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d https://example.com
  %(prog)s -d example.com -o my_js_files
  %(prog)s -d https://example.com -m 100
  %(prog)s -d https://example.com --scan
  %(prog)s -d https://example.com -o my_js_files --scan
        """
    )
    
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Domain to download JS files from (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='downloaded_js',
        help='Output directory for downloaded files (default: downloaded_js)'
    )
    
    parser.add_argument(
        '-m', '--max-pages',
        type=int,
        default=50,
        help='Maximum number of pages to crawl (default: 50)'
    )
    
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Scan downloaded JS files for API keys, tokens, and secrets'
    )
    
    args = parser.parse_args()
    
    try:
        # Download JS files
        crawl_and_download_js(args.domain, args.output, args.max_pages)
        
        # Scan for secrets if flag is set
        if args.scan:
            scan_directory_for_secrets(args.output)
        
    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
