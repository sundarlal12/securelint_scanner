# extension_scraper.py
import re
import json
import requests
from bs4 import BeautifulSoup
from typing import Optional, List, Dict, Any
import logging
import concurrent.futures
import time
import ssl
import certifi
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom SSL Adapter to fix certificate issues
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1_2
        return super().init_poolmanager(*args, **kwargs)

# Create session with proper SSL handling
session = requests.Session()
session.mount('https://', SSLAdapter())
session.verify = certifi.where()

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_page(url: str, headers: dict, timeout: int = 15):
    """Fetch page with retry and SSL handling"""
    try:
        response = session.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        logger.error(f"Failed to fetch {url}: {e}")
        try:
            response = session.get(url, headers=headers, timeout=timeout, verify=False)
            response.raise_for_status()
            return response
        except:
            raise e

def parse_main_page(extension_id: str, html: str) -> Dict[str, Any]:
    """Parse main page data"""
    soup = BeautifulSoup(html, 'html.parser')
    result = {}
    
    # 1. Extract logo URL
    logo_img = soup.select_one('img[alt*="Item logo"], img.rBxtY, .VgVgxc img')
    if logo_img:
        result['logo_url'] = logo_img.get('src', '').split('=')[0]
    
    # 2. Extract name
    name_elem = soup.select_one('h1.Pa2dE, h1[itemprop="name"], .VgVgxc h1')
    if name_elem:
        result['name'] = name_elem.text.strip()
    
    # 3. Extract description
    desc_elem = soup.select_one('.mN52G, .CszwBe, .S1Lljf')
    if desc_elem:
        first_p = desc_elem.find('p')
        result['description'] = first_p.text.strip() if first_p else desc_elem.text.strip()[:500]
    
    # 4. Extract rating and users
    rating_elem = soup.select_one('.Vq0ZA')
    if rating_elem:
        try:
            result['star_rating'] = float(rating_elem.text.strip())
        except:
            pass
    
    rating_count_elem = soup.select_one('.GvZmud, [aria-label*="ratings"]')
    if rating_count_elem:
        aria_label = rating_count_elem.get('aria-label', '')
        match = re.search(r'(\d+[\d,]*)', aria_label)
        if match:
            result['rating_count'] = int(match.group(1).replace(',', ''))
    
    users_elem = soup.select_one('.F9iKBc')
    if users_elem:
        users_text = users_elem.get_text()
        match = re.search(r'([\d,]+\s*users?)', users_text, re.I)
        if match:
            result['users'] = match.group(1)
    
    # 5. Extract category
    category_links = soup.select('.F9iKBc a.gqpEIe')
    if category_links:
        result['category'] = category_links[0].text.strip()
        if len(category_links) > 1:
            result['category_path'] = [cat.text.strip() for cat in category_links]
    
    # 6. Extract details from Details section
    details_section = soup.select_one('.TKAMQe, .im4wIf')
    if details_section:
        detail_items = details_section.select('.MqICNe')
        
        for item in detail_items:
            label_elem = item.select_one('.QDHp8e')
            value_elem = item.select_one('.nBZElf, div:not(.QDHp8e)')
            
            if not label_elem:
                continue
                
            label = label_elem.text.strip().lower()
            value = value_elem.text.strip() if value_elem else ""
            
            if 'version' in label:
                result['version'] = value
            elif 'updated' in label:
                result['updated_date'] = value
            elif 'size' in label:
                result['size'] = value
            elif 'language' in label:
                result['languages'] = [lang.strip() for lang in value.split(',')] if value else []
            elif 'developer' in label:
                dev_div = item.select_one('.yyjN4, .mdSapd')
                if dev_div:
                    result['developer_address'] = dev_div.text.strip()
                    lines = dev_div.text.strip().split('\n')
                    if lines:
                        result['developer_name'] = lines[0].strip()
                
                website_link = item.select_one('a.Qk4pd, a[href*="http"]')
                if website_link:
                    result['developer_website'] = website_link.get('href')
                
                email_elem = item.select_one('.NnJuub')
                if email_elem:
                    result['developer_email'] = email_elem.text.strip()
                
                phone_elem = item.select_one('.sQlfnf')
                if phone_elem:
                    result['developer_phone'] = phone_elem.text.strip()
            
            elif 'features' in label:
                result['features'] = [value] if value else []
    
    # 7. Extract support website
    support_link = soup.select_one('.kcASRe a.YeLZxd')
    if support_link:
        result['support_website'] = support_link.get('href')
    
    # 8. Extract from JSON-LD
    json_ld = soup.find('script', type='application/ld+json')
    if json_ld and json_ld.string:
        try:
            data = json.loads(json_ld.string)
            if not result.get('name') and 'name' in data:
                result['name'] = data['name']
            if not result.get('description') and 'description' in data:
                result['description'] = data['description']
            if 'aggregateRating' in data:
                if not result.get('star_rating'):
                    result['star_rating'] = data['aggregateRating'].get('ratingValue')
                if not result.get('rating_count'):
                    result['rating_count'] = data['aggregateRating'].get('ratingCount')
        except:
            pass
    
    # 9. Extract permissions
    script_tags = soup.find_all('script')
    for script in script_tags:
        if script.string and 'manifest_version' in script.string:
            manifest_match = re.search(r'"permissions"\s*:\s*\[(.*?)\]', script.string, re.DOTALL)
            if manifest_match:
                perms_str = manifest_match.group(1)
                permissions = re.findall(r'"([^"]+)"', perms_str)
                if permissions:
                    result['permissions'] = permissions[:10]
            break
    
    return result

def parse_privacy_page(html: str) -> Dict[str, Any]:
    """Parse privacy page data"""
    if not html:
        return {}
    
    soup = BeautifulSoup(html, 'html.parser')
    result = {}
    
    policy_link = soup.select_one('.S7w4Mb a.SYhWge')
    if policy_link:
        result['privacy_policy_url'] = policy_link.get('href')
    
    data_items = soup.select('.IbuSnc, .BeFehc')
    data_handled = []
    for item in data_items:
        h4 = item.select_one('h4.FNNqG, .jnapE')
        if h4:
            data_handled.append(h4.text.strip())
    if data_handled:
        result['data_handled'] = data_handled
    
    policy_items = soup.select('.LH0qne')
    if policy_items:
        result['data_usage_policy'] = [item.text.strip() for item in policy_items]
    
    return result

async def fetch_extension_details(extension_id: str) -> Dict[str, Any]:
    """Fetch extension details using threading for parallel requests"""
    start_time = time.time()
    
    main_url = f"https://chromewebstore.google.com/detail/{extension_id}"
    privacy_url = f"https://chromewebstore.google.com/detail/{extension_id}/privacy"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    results = {}
    
    # Use ThreadPoolExecutor for parallel fetching
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        main_future = executor.submit(fetch_page, main_url, headers, 15)
        privacy_future = executor.submit(fetch_page, privacy_url, headers, 10)
        
        try:
            main_response = main_future.result()
            results['main_html'] = main_response.text
        except Exception as e:
            logger.error(f"Failed to fetch main page: {e}")
            return {"id": extension_id, "error": f"Extension {extension_id} not found"}
        
        try:
            privacy_response = privacy_future.result()
            results['privacy_html'] = privacy_response.text
        except:
            results['privacy_html'] = None
            logger.warning(f"Could not fetch privacy page for {extension_id}")
    
    # Parse both pages in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as parser_executor:
        main_parse_future = parser_executor.submit(parse_main_page, extension_id, results['main_html'])
        privacy_parse_future = parser_executor.submit(parse_privacy_page, results['privacy_html'])
        
        main_data = main_parse_future.result()
        privacy_data = privacy_parse_future.result()
    
    # Combine all data
    all_data = {
        "id": extension_id,
        **main_data,
        **privacy_data,
        "response_time_ms": round((time.time() - start_time) * 1000, 2)
    }
    
    logger.info(f"Fetched {extension_id} in {all_data['response_time_ms']}ms")
    
    return all_data