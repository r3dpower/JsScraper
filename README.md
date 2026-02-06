# JsScraper
A Python script that crawls a domain and downloads all JavaScript files, handling both absolute and relative URLs.

## Features
- Crawls web pages to find all .js file references
- Handles both absolute and relative URLs
- Preserves directory structure from URLs
- Built-in secret scanner for detecting API keys, tokens, and credentials
- Scans for 35+ common secret patterns (AWS, GitHub, Slack, Stripe, etc.)
- Generates detailed JSON reports of findings
- Configurable output directory
- Configurable crawl depth (max pages)
- Session-based requests for efficiency

## Installation
```bash
pip install -r requirements.txt
```

## Usage
1. For a simple run:
```bash
python3 JsScraper.py -d https://example.com -o results
```
2. Increase Crawl Limit
```bash
python3 JsScraper.py -d https://example.com -o results -m 100
```
3. Scan for secrets on downloaded JS files
```bash
python3 JsScraper.py -d https://example.com -o results --scan
```

## Secret Detection
The --scan flag activates the built-in secret scanner that detects 35+ patterns including:
- General Patterns (JWT, Private Keys, Passwords, Firebase)
- Cloud Providers (AWS, Azure, GCP)
- Version Control (GitHub & GitLab tokens)
- Communication Platforms (Discord & Slack)
- Payment Services (Stripe & Square)
- Developer Tools (NPM, PyPi, Heroku)
- Email Services (SendGrid, MailChimp, Mailgun)
- Social Media (Twitter/X, Facebook)

## How It Works
1. Crawling: Starts from the given domain and crawls pages (staying within the same domain)
2. Extraction: Finds all JavaScript file references in:
  - <script src="..."> tags
  - String references to .js files in HTML
3. URL Resolution: Converts relative URLs to absolute URLs
4. Downloading: Downloads each unique JS file to the output directory
5. File Organization: Preserves the URL path structure in the local filesystem
