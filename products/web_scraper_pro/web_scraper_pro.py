#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
WebScraper Pro - Universal E-commerce Data Extractor
Professional web scraping tool for product data extraction

License: Commercial (included with purchase)
"""

import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import time
import logging
from pathlib import Path
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WebScraperPro:
    """Professional web scraping engine"""
    
    def __init__(self, config_file='config.json'):
        """Initialize scraper with configuration"""
        self.config = self.load_config(config_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.products = []
        
    def load_config(self, config_file):
        """Load configuration from JSON"""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def fetch_page(self, url):
        """Fetch page with error handling"""
        try:
            logger.info(f"Fetching: {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            # Rate limiting
            delay = self.config.get('rate_limit', {}).get('delay_seconds', 1)
            time.sleep(delay)
            
            return response.text
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
    
    def extract_text(self, soup, selector):
        """Extract text from selector"""
        try:
            element = soup.select_one(selector)
            if element:
                return element.get_text(strip=True)
        except Exception as e:
            logger.warning(f"Error extracting {selector}: {e}")
        return ""
    
    def extract_attribute(self, soup, selector, attribute='src'):
        """Extract attribute from selector"""
        try:
            element = soup.select_one(selector)
            if element:
                value = element.get(attribute, '')
                # Make absolute URL if relative
                if value and not value.startswith('http'):
                    base_url = self.config.get('target_url', '')
                    value = urljoin(base_url, value)
                return value
        except Exception as e:
            logger.warning(f"Error extracting attribute {selector}: {e}")
        return ""
    
    def extract_price(self, price_text):
        """Extract numeric price from text"""
        try:
            # Remove currency symbols and extract number
            numbers = re.findall(r'[\d,]+\.?\d*', price_text)
            if numbers:
                return float(numbers[0].replace(',', ''))
        except:
            pass
        return 0.0
    
    def scrape_product(self, soup):
        """Extract product data from page"""
        selectors = self.config.get('selectors', {})
        
        product = {}
        
        # Title
        product['title'] = self.extract_text(soup, selectors.get('product_title', ''))
        
        # Price
        price_text = self.extract_text(soup, selectors.get('price', ''))
        product['price'] = self.extract_price(price_text)
        product['price_text'] = price_text
        
        # Image
        product['image_url'] = self.extract_attribute(
            soup, 
            selectors.get('image', ''), 
            'src'
        )
        
        # Description
        product['description'] = self.extract_text(soup, selectors.get('description', ''))
        
        # SKU/ID (if available)
        product['sku'] = self.extract_text(soup, selectors.get('sku', ''))
        
        # Rating (if available)
        product['rating'] = self.extract_text(soup, selectors.get('rating', ''))
        
        # Availability
        product['availability'] = self.extract_text(soup, selectors.get('availability', ''))
        
        # URL
        product['url'] = self.config.get('current_url', '')
        
        # Timestamp
        product['scraped_at'] = datetime.now().isoformat()
        
        return product
    
    def scrape_listing_page(self, url):
        """Scrape products from listing page"""
        html = self.fetch_page(url)
        if not html:
            return []
        
        soup = BeautifulSoup(html, 'lxml')
        products = []
        
        # Get product containers
        container_selector = self.config.get('selectors', {}).get('product_container', '.product')
        containers = soup.select(container_selector)
        
        logger.info(f"Found {len(containers)} products")
        
        for container in containers:
            try:
                product = self.scrape_product_from_container(container)
                if product and product.get('title'):
                    products.append(product)
            except Exception as e:
                logger.error(f"Error scraping product: {e}")
                continue
        
        return products
    
    def scrape_product_from_container(self, container):
        """Extract product from container element"""
        selectors = self.config.get('selectors', {})
        
        product = {}
        product['title'] = self.extract_text(container, selectors.get('product_title', ''))
        
        price_text = self.extract_text(container, selectors.get('price', ''))
        product['price'] = self.extract_price(price_text)
        product['price_text'] = price_text
        
        product['image_url'] = self.extract_attribute(container, selectors.get('image', ''), 'src')
        
        # Product link
        link_selector = selectors.get('product_link', 'a')
        product['url'] = self.extract_attribute(container, link_selector, 'href')
        
        product['scraped_at'] = datetime.now().isoformat()
        
        return product
    
    def get_next_page_url(self, soup, current_url):
        """Get next page URL for pagination"""
        pagination = self.config.get('pagination', {})
        if not pagination.get('enabled', False):
            return None
        
        next_selector = pagination.get('next_button', '.next')
        next_element = soup.select_one(next_selector)
        
        if next_element:
            next_url = next_element.get('href', '')
            if next_url:
                return urljoin(current_url, next_url)
        
        return None
    
    def scrape_all_pages(self):
        """Scrape all pages with pagination"""
        url = self.config.get('target_url')
        page = 1
        max_pages = self.config.get('pagination', {}).get('max_pages', 10)
        
        all_products = []
        
        while url and page <= max_pages:
            logger.info(f"Scraping page {page}: {url}")
            
            html = self.fetch_page(url)
            if not html:
                break
            
            soup = BeautifulSoup(html, 'lxml')
            products = self.scrape_listing_page(url)
            all_products.extend(products)
            
            logger.info(f"Page {page}: Found {len(products)} products (Total: {len(all_products)})")
            
            # Get next page
            url = self.get_next_page_url(soup, url)
            page += 1
        
        self.products = all_products
        return all_products
    
    def save_to_csv(self, filename=None):
        """Save products to CSV"""
        if not self.products:
            logger.warning("No products to save")
            return
        
        if not filename:
            output_config = self.config.get('output', {})
            filename = output_config.get('filename', f'products_{datetime.now().strftime("%Y%m%d")}.csv')
        
        # Create output directory
        output_dir = Path('data')
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / filename
        
        df = pd.DataFrame(self.products)
        df.to_csv(filepath, index=False)
        
        logger.info(f"✅ Saved {len(self.products)} products to {filepath}")
        return filepath
    
    def save_to_excel(self, filename=None):
        """Save products to Excel"""
        if not self.products:
            logger.warning("No products to save")
            return
        
        if not filename:
            filename = f'products_{datetime.now().strftime("%Y%m%d")}.xlsx'
        
        output_dir = Path('data')
        output_dir.mkdir(exist_ok=True)
        filepath = output_dir / filename
        
        df = pd.DataFrame(self.products)
        df.to_excel(filepath, index=False)
        
        logger.info(f"✅ Saved {len(self.products)} products to {filepath}")
        return filepath
    
    def run(self):
        """Main execution"""
        logger.info("🕷️  WebScraper Pro - Starting")
        logger.info(f"Target: {self.config.get('target_url')}")
        
        # Scrape
        products = self.scrape_all_pages()
        
        # Save
        output_format = self.config.get('output', {}).get('format', 'csv')
        if output_format == 'excel':
            self.save_to_excel()
        else:
            self.save_to_csv()
        
        logger.info(f"✅ Complete! Scraped {len(products)} products")
        
        return products


def main():
    """Entry point"""
    scraper = WebScraperPro('config.json')
    scraper.run()


if __name__ == '__main__':
    main()
