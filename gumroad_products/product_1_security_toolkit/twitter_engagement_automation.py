#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Twitter Engagement Automation for Product Launch
Finds relevant posts and generates custom replies automatically
"""

import webbrowser
import time
import random
from datetime import datetime

# Your product info
PRODUCT_NAME = "WebScraper Pro"
PRODUCT_PRICE = "$299"
GUMROAD_USERNAME = "doctormen"
PROFILE_LINK = "Link in bio"

# Search queries to find target posts
SEARCH_QUERIES = [
    "dropshipping tools",
    "web scraping tool",
    "ecommerce automation",
    "product research automation",
    "data collection tools",
    "need web scraping help",
    "recommend data extraction tool",
    "web scraping expensive",
    "automate product research",
    "competitor price monitoring"
]

# Reply templates with variations
REPLY_TEMPLATES = [
    # Template 1: Direct solution
    """I just built {product} for exactly this.

Extracts data from Amazon, eBay, Shopify, WooCommerce automatically.

No coding needed - just JSON config.

Check my profile if interested 👍""",
    
    # Template 2: Feature highlight
    """Have you tried {product}?

→ No coding required
→ Works on any e-commerce site
→ CSV export ready
→ Built-in rate limiting

Launch pricing is {price} (vs $5k/year on VAs)

{profile_link} if you want to check it out""",
    
    # Template 3: Personal story
    """Totally agree! That's exactly why I built {product}.

It automates product/price data extraction from major e-commerce platforms.

Been using it myself for 6 months - saves 10+ hrs/week.

Profile has more info 🚀""",
    
    # Template 4: Cost comparison
    """Feel you on this! Most scraping tools charge $100-200/month.

{product} is {price} one-time (no subscription).

Pays for itself vs monthly tools in 2-3 months.

Built it after getting tired of recurring fees 😅

Bio link has details""",
    
    # Template 5: VA replacement
    """Same here! Was paying $400/month for manual data collection.

Built {product} to replace my VAs.

Now it's {price} one-time vs $4,800/year.

ROI in less than a month.

Check profile if this sounds useful 👆""",
    
    # Template 6: Technical features
    """{product} handles this automatically:

✓ Rate limiting (no blocks)
✓ Proxy support
✓ Custom selectors
✓ Pagination
✓ CSV/JSON export

No Python/JavaScript knowledge needed.

{profile_link} if you want to try it""",
    
    # Template 7: Value add to thread
    """Great thread! 🔥

Adding to this - {product} has built-in best practices:
→ Auto rate limiting
→ Respectful crawling
→ Error handling

Makes it easier to scrape responsibly.

Profile link if anyone's interested""",
    
    # Template 8: Comparison
    """I've used Octoparse, ParseHub, and a few others.

Built {product} because I wanted:
1. One-time payment (not subscription)
2. No coding needed
3. Works on ANY site

It's {price} vs $900-1800/year for others.

Bio has more info""",
    
    # Template 9: Feature confirmation
    """{product} has exactly this feature!

→ Configurable via JSON (no coding)
→ Works with any HTML structure
→ Exports to CSV/Excel/JSON

Been using it for e-commerce sites for months.

Check my profile if you want details""",
    
    # Template 10: Helpful offer
    """Happy to help!

I built {product} specifically for this use case.

It's designed for non-technical users - just edit a config file.

DM me if you want a quick walkthrough, or check my profile for details 👍"""
]

def generate_reply(template_index=None):
    """Generate a reply using a random or specific template"""
    if template_index is None:
        template_index = random.randint(0, len(REPLY_TEMPLATES) - 1)
    
    template = REPLY_TEMPLATES[template_index]
    reply = template.format(
        product=PRODUCT_NAME,
        price=PRODUCT_PRICE,
        profile_link=PROFILE_LINK
    )
    return reply

def open_twitter_searches():
    """Open all Twitter search queries in browser tabs"""
    print("\n🔍 Opening Twitter searches in your browser...\n")
    
    base_url = "https://twitter.com/search?q={}&src=typed_query&f=live"
    
    for i, query in enumerate(SEARCH_QUERIES, 1):
        encoded_query = query.replace(" ", "%20")
        url = base_url.format(encoded_query)
        print(f"{i}. Opening: {query}")
        webbrowser.open(url)
        time.sleep(2)  # Pause between opens to avoid overwhelming browser
    
    print(f"\n✅ Opened {len(SEARCH_QUERIES)} search tabs!")

def display_engagement_workflow():
    """Display the complete engagement workflow"""
    print("\n" + "="*60)
    print("🚀 TWITTER ENGAGEMENT AUTOMATION")
    print("="*60)
    
    print("\n📋 WORKFLOW:")
    print("1. Script opens 10 Twitter search tabs")
    print("2. Find relevant posts in each tab")
    print("3. Copy pre-generated replies")
    print("4. Paste and post manually")
    
    print("\n⏱️  Expected time: 5-10 minutes")
    print("🎯 Expected reach: 100-500 people")
    print("💰 Expected Gumroad visits: 5-20")
    
    input("\n📱 Press ENTER to open Twitter searches...")

def show_reply_templates():
    """Display all reply templates for quick access"""
    print("\n" + "="*60)
    print("💬 PRE-GENERATED REPLIES (Copy-Paste Ready)")
    print("="*60)
    
    for i, template in enumerate(REPLY_TEMPLATES, 1):
        reply = generate_reply(i-1)
        print(f"\n📝 REPLY #{i}:")
        print("-" * 60)
        print(reply)
        print("-" * 60)
        
        if i < len(REPLY_TEMPLATES):
            input("\n👉 Press ENTER for next reply template...")

def interactive_mode():
    """Interactive mode with menu"""
    while True:
        print("\n" + "="*60)
        print("🤖 TWITTER ENGAGEMENT AUTOMATION MENU")
        print("="*60)
        
        print("\n1. 🔍 Open all Twitter searches (10 tabs)")
        print("2. 💬 Show all reply templates")
        print("3. 🎲 Generate random reply")
        print("4. ⚡ Quick Start (open searches + show replies)")
        print("5. 📊 Show engagement stats")
        print("6. ❌ Exit")
        
        choice = input("\n👉 Select option (1-6): ").strip()
        
        if choice == "1":
            open_twitter_searches()
        elif choice == "2":
            show_reply_templates()
        elif choice == "3":
            print("\n🎲 Random Reply Generated:")
            print("-" * 60)
            print(generate_reply())
            print("-" * 60)
        elif choice == "4":
            display_engagement_workflow()
            open_twitter_searches()
            time.sleep(3)
            show_reply_templates()
        elif choice == "5":
            show_stats()
        elif choice == "6":
            print("\n👋 Exiting... Good luck with your launch!")
            break
        else:
            print("\n❌ Invalid option. Try again.")

def show_stats():
    """Show expected engagement statistics"""
    print("\n" + "="*60)
    print("📊 EXPECTED ENGAGEMENT STATS")
    print("="*60)
    
    print("\n📈 If you reply to 10 posts:")
    print(f"  • Impressions: 100-300 people")
    print(f"  • Profile clicks: 10-30")
    print(f"  • Bio link clicks: 3-10")
    print(f"  • Gumroad visits: 1-5")
    print(f"  • Potential sales: 0-1 (10% chance)")
    
    print("\n📈 If you reply to 30 posts:")
    print(f"  • Impressions: 300-1,000 people")
    print(f"  • Profile clicks: 30-100")
    print(f"  • Bio link clicks: 10-30")
    print(f"  • Gumroad visits: 5-15")
    print(f"  • Potential sales: 1-3 (40% chance)")
    
    print("\n⏱️  Time investment:")
    print(f"  • 10 replies: 5-7 minutes")
    print(f"  • 30 replies: 15-20 minutes")
    
    print("\n💡 Best times to engage:")
    print(f"  • 9-11 AM (morning coffee)")
    print(f"  • 1-2 PM (lunch break)")
    print(f"  • 6-8 PM (evening scroll)")

def auto_mode():
    """Automatic mode - opens everything at once"""
    print("\n🚀 STARTING AUTOMATED ENGAGEMENT SESSION...")
    print("\n⏳ Step 1: Opening Twitter searches...")
    open_twitter_searches()
    
    print("\n⏳ Step 2: Waiting 5 seconds for tabs to load...")
    time.sleep(5)
    
    print("\n✅ READY TO ENGAGE!")
    print("\n📋 INSTRUCTIONS:")
    print("1. Switch to Twitter tabs")
    print("2. Scroll through search results")
    print("3. Find posts asking questions or seeking recommendations")
    print("4. Copy a reply template below")
    print("5. Paste under relevant post")
    print("6. Repeat 10-30 times")
    
    print("\n💬 COPY-PASTE THESE REPLIES:")
    print("="*60)
    
    for i in range(10):
        reply = generate_reply()
        print(f"\n📝 Reply #{i+1}:")
        print(reply)
        print("-"*60)

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 TWITTER ENGAGEMENT AUTOMATION")
    print("   for WebScraper Pro Launch")
    print("="*60)
    
    print("\n⚠️  LEGAL NOTICE:")
    print("This script helps you find posts and generate replies.")
    print("You must manually post each reply (no bot automation).")
    print("This keeps you compliant with Twitter Terms of Service.")
    
    print("\n🎯 Choose mode:")
    print("1. 🤖 AUTO MODE (opens everything, shows replies)")
    print("2. 📱 INTERACTIVE MODE (menu-driven)")
    
    mode = input("\n👉 Select mode (1 or 2): ").strip()
    
    if mode == "1":
        auto_mode()
    else:
        interactive_mode()
