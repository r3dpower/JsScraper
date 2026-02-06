# JsScraper
A Python script that crawls a domain and downloads all JavaScript files, handling both absolute and relative URLs.

## Features
- Crawls web pages to find all .js file references
- Handles both absolute and relative URLs
- Preserves directory structure from URLs
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

## How It Works
1. Crawling: Starts from the given domain and crawls pages (staying within the same domain)
2. Extraction: Finds all JavaScript file references in:
  - <script src="..."> tags
  - String references to .js files in HTML
3. URL Resolution: Converts relative URLs to absolute URLs
4. Downloading: Downloads each unique JS file to the output directory
5. File Organization: Preserves the URL path structure in the local filesystem
