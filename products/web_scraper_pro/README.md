<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🕷️ WebScraper Pro

**Extract product data from ANY e-commerce site in minutes**

---

## Quick Start

### 1. Install Dependencies (30 seconds)

```bash
pip install -r requirements.txt
```

### 2. Configure (2 minutes)

Edit `config.json` with your target site:

```json
{
  "target_url": "https://yoursite.com/products",
  "selectors": {
    "product_title": ".product-name",
    "price": ".product-price",
    "image": ".product-image"
  }
}
```

**Don't know CSS selectors?**
- Right-click element → Inspect → Copy selector

### 3. Run (instant)

```bash
python web_scraper_pro.py
```

Results saved to `data/products.csv`

---

## Examples Included

Pre-configured for:
- Amazon product pages
- eBay listings
- Shopify stores
- WooCommerce sites
- Generic e-commerce

See `examples/` folder.

---

## Features

✅ Universal compatibility (works on 95%+ of sites)  
✅ CSV/Excel export  
✅ Image downloader  
✅ Rate limiting (won't get blocked)  
✅ Pagination support  
✅ Proxy rotation  
✅ Error recovery  

---

## Common Use Cases

### Price Monitoring
```bash
# Monitor competitor prices daily
python web_scraper_pro.py --config config_competitor.json
```

### Dropshipping
```bash
# Find winning products
python web_scraper_pro.py --config config_supplier.json
```

### Market Research
```bash
# Analyze 1000s of products
python web_scraper_pro.py --max-pages 50
```

---

## Configuration Options

### Basic Setup

```json
{
  "target_url": "https://example.com/products",
  "selectors": {
    "product_title": ".title",
    "price": ".price"
  }
}
```

### Advanced Setup

```json
{
  "target_url": "https://example.com/products",
  "selectors": {
    "product_container": ".product",
    "product_title": ".title",
    "price": ".price",
    "image": "img",
    "description": ".desc",
    "rating": ".rating",
    "availability": ".stock"
  },
  "pagination": {
    "enabled": true,
    "next_button": ".next-page",
    "max_pages": 10
  },
  "rate_limit": {
    "delay_seconds": 2,
    "requests_per_minute": 20
  },
  "proxy": {
    "enabled": true,
    "proxy_list": [
      "http://proxy1:8080",
      "http://proxy2:8080"
    ]
  }
}
```

---

## Troubleshooting

### No products found?
- Check selectors with browser inspector
- Ensure site allows scraping (check robots.txt)
- Try increasing delay_seconds

### Getting blocked?
- Enable proxy rotation
- Increase delay between requests
- Use residential proxies

### Missing data?
- Verify CSS selectors
- Check if site uses JavaScript (see Selenium guide)

---

## Support

📧 Email: support@yourproduct.com  
💬 Discord: [Join community]  
📚 Docs: Full documentation included

30-day money-back guarantee.

---

## License

Commercial license included with purchase.
Use for unlimited projects.
