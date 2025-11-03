#!/usr/bin/env python3
import os, re, sys

CONFIG_PATH = os.path.join('docs','config.js')
keys = {
    'stripeCheckoutUrl': os.environ.get('STRIPE_CHECKOUT_URL'),
    'stripeExpressUrl': os.environ.get('STRIPE_EXPRESS_URL'),
    'stripeMonthlyUrl': os.environ.get('STRIPE_MONTHLY_URL'),
    'googleFormUrl': os.environ.get('GOOGLE_FORM_URL'),
    'calendlyUrl': os.environ.get('CALENDLY_URL'),
}
slots = os.environ.get('SLOTS_REMAINING')

if not os.path.isfile(CONFIG_PATH):
    print('config.js not found at docs/config.js', file=sys.stderr)
    sys.exit(1)

with open(CONFIG_PATH,'r',encoding='utf-8') as f:
    src = f.read()

changed = 0
for k,v in keys.items():
    if v:
        pattern = re.compile(rf"({k}\s*:\s*')[^']*(')")
        # Use \g<1> to avoid backref + digit ambiguity (e.g., \13)
        src, n = re.subn(pattern, lambda m: m.group(1) + re.escape(v) + m.group(2), src)
        changed += n

if slots:
    try:
        s = int(slots)
        pattern = re.compile(r"(slotsRemaining\s*:\s*)\d+")
        src, n = re.subn(pattern, lambda m: m.group(1) + str(s), src)
        changed += n
    except ValueError:
        pass

with open(CONFIG_PATH,'w',encoding='utf-8') as f:
    f.write(src)

print(f'Updated config.js fields: {changed}')


