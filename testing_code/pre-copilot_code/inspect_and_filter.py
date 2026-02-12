import os
import json
import time
import argparse
import logging
import requests
import gzip
import csv
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from config import *
import re

os.makedirs(JSON_SAVE_DIR, exist_ok=True)
logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")

def fetch_html(url, session):
    try: 
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logging.warning(f"failed to fetch HTML {url}:{e}")
        return None

def find_url_from_page(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a",href=True):
        href =a["href"].strip()
        full = urljoin(base_url,href)
        if full.lower().endswith(".json"):
            return full

    for a in soup.find_all("a",href=True):
        href = a["href"].strip()
        full = urljoin(base_url,href)
        if "download" in full.lower() or "json" in full.lower():
            return full
        
    
    link = soup.find("link", attrs={"type": "application/json"})
    if link and link.get("href"):
        return urljoin(base_url, link["href"])
    
    return None

url = "https://malfe.cs.up.ac.za/reports/"
session = requests.Session()

html = fetch_html(url,session)
html = session.get(url).text

json_url = find_url_from_page(html, url)
print("Found JSON URL:", json_url)

def extract_sample_metadata(html):
    soup = BeautifulSoup(html, "html.parser")
    meta = {"category": None,"sample_sha256": None, "report_sha256":None}

    text = soup.get_text(separator="\n")
    # Extract SHA256 values (64 hex characters)
    sample_match = re.search(r"sample sha256:\s*([a-fA-F0-9]{64})", text, re.IGNORECASE)
    report_match = re.search(r"report sha256:\s*([a-fA-F0-9]{64})", text, re.IGNORECASE)
    category_match = re.search(r"category:\s*([^\n]+)", text, re.IGNORECASE)

    if sample_match:
        meta["sample_sha256"] = sample_match.group(1)
    if report_match:
        meta["report_sha256"] = report_match.group(1)
    if category_match:
        meta["category"] = category_match.group(1).strip()

    return meta
    
extract_sample_metadata(html)   

    