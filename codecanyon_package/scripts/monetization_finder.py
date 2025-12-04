#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Monetization Strategy Finder
Analyzes your learning data and suggests ways to make money
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

class MonetizationFinder:
    def __init__(self):
        self.strategies = []
        
    def analyze_learning_data(self, learning_entries):
        """Analyze learning data and generate monetization strategies"""
        
        if not learning_entries:
            return {
                'total_compound': 0,
                'strategies': [{
                    'type': 'Get Started',
                    'reasoning': 'No learning data yet - start tracking!',
                    'action': 'Add learning entries to build your knowledge base',
                    'potential': 'N/A'
                }]
            }
        
        # Calculate metrics
        total_compound = sum(e.get('compoundEffect', 1) for e in learning_entries)
        high_impact = [e for e in learning_entries if e.get('impact') == 'high']
        medium_impact = [e for e in learning_entries if e.get('impact') == 'medium']
        
        # Category analysis
        categories = defaultdict(list)
        for entry in learning_entries:
            cat = entry.get('category', 'General')
            if cat:
                categories[cat].append(entry)
        
        # Time analysis
        now = datetime.now()
        this_month = [e for e in learning_entries if self._is_this_month(e.get('date'))]
        
        # Keyword analysis
        all_titles = ' '.join(e.get('title', '').lower() for e in learning_entries)
        keywords = self._extract_keywords(all_titles)
        
        # Generate strategies
        strategies = []
        
        # Strategy 1: Premium Consulting (if compound > 20x)
        if total_compound >= 20:
            hourly_rate = min(500, int(total_compound * 5))
            annual_potential = hourly_rate * 20 * 48  # 20 hrs/week, 48 weeks
            strategies.append({
                'type': '🎯 Premium Consulting',
                'reasoning': f'Your {total_compound:.1f}x compound knowledge = expert level',
                'pricing': f'${hourly_rate-50}-{hourly_rate}/hour',
                'action': 'Position yourself as premium consultant in top categories',
                'categories': list(categories.keys())[:3],
                'potential': f'${annual_potential:,}/year (20hrs/week)',
                'priority': 'HIGH'
            })
        
        # Strategy 2: Online Course (if 5+ high impact)
        if len(high_impact) >= 5:
            course_price = 497 if len(high_impact) < 10 else 997
            strategies.append({
                'type': '📚 Online Course Creation',
                'reasoning': f'{len(high_impact)} high-impact skills worth teaching',
                'pricing': f'${course_price} per student',
                'action': f'Create course on: {", ".join(e["title"][:30] for e in high_impact[:3])}',
                'potential': f'${course_price * 100:,} (100 students) to ${course_price * 500:,} (500 students)',
                'priority': 'HIGH' if len(high_impact) >= 8 else 'MEDIUM'
            })
        
        # Strategy 3: Multiple Service Streams (if 3+ categories)
        if len(categories) >= 3:
            income_per_stream = 5000
            total_monthly = income_per_stream * len(categories)
            strategies.append({
                'type': '🎨 Multiple Revenue Streams',
                'reasoning': f'{len(categories)} distinct expertise domains',
                'pricing': '$150-300/hour per service type',
                'action': f'Offer separate services for: {", ".join(categories.keys())}',
                'potential': f'${total_monthly:,}/month ({len(categories)} streams × ${income_per_stream:,})',
                'priority': 'MEDIUM'
            })
        
        # Strategy 4: Automation Products (if automation mentioned)
        automation_count = sum(1 for e in learning_entries 
                              if 'automation' in e.get('title', '').lower() 
                              or 'automation' in e.get('description', '').lower())
        if automation_count >= 3:
            strategies.append({
                'type': '🤖 Automation Tools/SaaS',
                'reasoning': f'{automation_count} automation-related learnings = productizable knowledge',
                'pricing': '$297-997/month subscription',
                'action': 'Build SaaS product from your automation expertise',
                'potential': '$30,000/month (100 customers) to $100,000/month (300 customers)',
                'priority': 'HIGH'
            })
        
        # Strategy 5: Template Sales (if patterns identified)
        if len(learning_entries) >= 10:
            strategies.append({
                'type': '📋 Template & Framework Sales',
                'reasoning': f'{len(learning_entries)} learnings can be packaged as templates',
                'pricing': '$97-297 per template pack',
                'action': 'Create templates/frameworks from your proven methods',
                'potential': '$9,700 (100 sales) to $29,700 (100 sales at $297)',
                'priority': 'MEDIUM'
            })
        
        # Strategy 6: Retainer Model (if compound growing)
        if len(this_month) >= 3:
            monthly_growth = len(this_month) / max(1, len(learning_entries))
            if monthly_growth > 0.2:  # Growing fast
                strategies.append({
                    'type': '🔒 Retainer Contracts',
                    'reasoning': f'Fast learning curve ({len(this_month)} entries this month) = increasing value',
                    'pricing': '$10,000-25,000/month retainer',
                    'action': 'Offer retainers with "lock in now before rates increase" messaging',
                    'potential': '$60,000-150,000 (6-month contracts)',
                    'priority': 'MEDIUM'
                })
        
        # Strategy 7: Done-For-You Services (if technical skills)
        technical_count = sum(1 for e in learning_entries
                             if any(word in e.get('title', '').lower() 
                                   for word in ['python', 'react', 'api', 'automation', 'system', 'code']))
        if technical_count >= 5:
            strategies.append({
                'type': '⚙️ Done-For-You Implementation',
                'reasoning': f'{technical_count} technical skills = can build complete solutions',
                'pricing': '$50,000-150,000 per implementation',
                'action': 'Offer complete implementation services (not just consulting)',
                'potential': '$50,000-150,000 per project (1-2 per month)',
                'priority': 'HIGH' if technical_count >= 10 else 'MEDIUM'
            })
        
        # Strategy 8: Niche Specialization (if unique combinations)
        if len(categories) >= 2 and total_compound >= 15:
            top_cats = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)[:2]
            niche = f"{top_cats[0][0]} + {top_cats[1][0]}"
            strategies.append({
                'type': '🎯 Niche Specialization',
                'reasoning': f'Unique combination: {niche}',
                'pricing': '2-3x market rate for specialized expertise',
                'action': f'Position as "{niche}" specialist (rare combination = premium)',
                'potential': '$200-400/hour vs $100-150/hour for generalists',
                'priority': 'HIGH'
            })
        
        # Sort by priority
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        strategies.sort(key=lambda x: priority_order.get(x.get('priority', 'LOW'), 3))
        
        return {
            'analysis_date': datetime.now().isoformat(),
            'metrics': {
                'total_entries': len(learning_entries),
                'total_compound_effect': round(total_compound, 1),
                'high_impact_entries': len(high_impact),
                'categories': len(categories),
                'entries_this_month': len(this_month)
            },
            'top_categories': list(categories.keys())[:5],
            'key_keywords': keywords[:10],
            'strategies': strategies,
            'summary': {
                'total_strategies': len(strategies),
                'high_priority': len([s for s in strategies if s.get('priority') == 'HIGH']),
                'estimated_potential': self._calculate_total_potential(strategies)
            }
        }
    
    def _is_this_month(self, date_str):
        """Check if date is in current month"""
        if not date_str:
            return False
        try:
            date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            now = datetime.now()
            return date.month == now.month and date.year == now.year
        except:
            return False
    
    def _extract_keywords(self, text):
        """Extract important keywords"""
        # Simple keyword extraction
        words = text.lower().split()
        # Filter out common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}
        keywords = [w for w in words if len(w) > 4 and w not in stop_words]
        counter = Counter(keywords)
        return [word for word, count in counter.most_common(10)]
    
    def _calculate_total_potential(self, strategies):
        """Calculate total potential from all strategies"""
        # Extract first number from potential string
        total = 0
        for strategy in strategies:
            potential = strategy.get('potential', '')
            # Try to extract first dollar amount
            import re
            amounts = re.findall(r'\$([0-9,]+)', potential)
            if amounts:
                amount = int(amounts[0].replace(',', ''))
                total += amount
        
        return f"${total:,}+ combined potential"


def load_learning_data():
    """Load learning data from various sources"""
    learning_entries = []
    
    # Try to load from app data (if exists)
    app_data_path = Path('business-transformation-app/data/learning.json')
    if app_data_path.exists():
        try:
            with open(app_data_path, 'r') as f:
                data = json.load(f)
                learning_entries.extend(data.get('entries', []))
        except:
            pass
    
    # Try to load from manual inputs
    manual_data_path = Path('output/manual_inputs.json')
    if manual_data_path.exists():
        try:
            with open(manual_data_path, 'r') as f:
                data = json.load(f)
                # Convert manual inputs to learning format
                for input_data in data.get('inputs', []):
                    learning_entries.append({
                        'title': input_data.get('input_type', 'Learning'),
                        'description': input_data.get('content', ''),
                        'category': input_data.get('input_type', 'General'),
                        'impact': 'medium',
                        'compoundEffect': 1.5,
                        'date': input_data.get('timestamp')
                    })
        except:
            pass
    
    return learning_entries


def print_analysis(analysis):
    """Pretty print analysis results"""
    
    print("\n" + "=" * 80)
    print("💰 MONETIZATION STRATEGY ANALYSIS")
    print("=" * 80)
    
    print("\n📊 YOUR LEARNING METRICS:")
    metrics = analysis['metrics']
    print(f"  • Total Learning Entries: {metrics['total_entries']}")
    print(f"  • Total Compound Effect: {metrics['total_compound_effect']}x")
    print(f"  • High Impact Entries: {metrics['high_impact_entries']}")
    print(f"  • Knowledge Categories: {metrics['categories']}")
    print(f"  • Entries This Month: {metrics['entries_this_month']}")
    
    if analysis.get('top_categories'):
        print(f"\n🎯 TOP CATEGORIES:")
        for cat in analysis['top_categories']:
            print(f"  • {cat}")
    
    print(f"\n💡 MONETIZATION STRATEGIES ({analysis['summary']['total_strategies']} found):")
    print(f"  ⚡ High Priority: {analysis['summary']['high_priority']}")
    print(f"  💰 Combined Potential: {analysis['summary']['estimated_potential']}")
    
    print("\n" + "=" * 80)
    
    for i, strategy in enumerate(analysis['strategies'], 1):
        priority_emoji = "🔴" if strategy.get('priority') == 'HIGH' else "🟡" if strategy.get('priority') == 'MEDIUM' else "🟢"
        print(f"\n{priority_emoji} STRATEGY #{i}: {strategy['type']}")
        print(f"  Priority: {strategy.get('priority', 'LOW')}")
        print(f"  Reasoning: {strategy['reasoning']}")
        print(f"  Pricing: {strategy['pricing']}")
        print(f"  Action: {strategy['action']}")
        print(f"  Potential: {strategy['potential']}")
        if 'categories' in strategy:
            print(f"  Categories: {', '.join(strategy['categories'])}")
    
    print("\n" + "=" * 80)
    print("💡 NEXT STEPS:")
    print("  1. Pick top 3 HIGH priority strategies")
    print("  2. Create specific offers for each")
    print("  3. Set up landing pages / portfolios")
    print("  4. Start marketing to potential clients")
    print("  5. Track results and iterate")
    print("=" * 80 + "\n")


def main():
    """Main entry point"""
    
    print("\n🔍 Loading learning data...")
    learning_entries = load_learning_data()
    
    if not learning_entries:
        print("\n⚠️  No learning data found!")
        print("\nTo get started:")
        print("  1. Add entries to your LearningSystem.tsx app")
        print("  2. Or capture manual inputs:")
        print("     python3 scripts/manual_input_learner.py capture skill 'Description' 'Context' 'Result'")
        print()
        return
    
    print(f"✅ Found {len(learning_entries)} learning entries\n")
    
    finder = MonetizationFinder()
    analysis = finder.analyze_learning_data(learning_entries)
    
    # Print analysis
    print_analysis(analysis)
    
    # Save to file
    output_path = Path('output/monetization_strategies.json')
    output_path.parent.mkdir(exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"📄 Full analysis saved to: {output_path}")
    print()


if __name__ == '__main__':
    main()
