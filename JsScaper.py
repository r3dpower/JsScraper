#!/usr/bin/env python3
"""
JavaScript File Downloader
Downloads all .js files from a given domain, handling both absolute and relative URLs.
"""

import argparse
import os
import re
import sys
from urllib.parse import urljoin, urlparse, unquote
from pathlib import Path

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install requests beautifulsoup4")
    sys.exit(1)


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
        description='Download all JavaScript files from a given domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d https://example.com
  %(prog)s -d example.com -o my_js_files
  %(prog)s -d https://example.com -m 100
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
    
    args = parser.parse_args()
    
    try:
        crawl_and_download_js(args.domain, args.output, args.max_pages)
    except KeyboardInterrupt:
        print("\n\nDownload interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
