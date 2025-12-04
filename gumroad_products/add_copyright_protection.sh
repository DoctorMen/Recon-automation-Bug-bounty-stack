#!/bin/bash
# Add Comprehensive Copyright Protection to All Gumroad Products
# Copyright © 2025 DoctorMen. All Rights Reserved.

echo "🔒 Adding Copyright Protection to All Products..."
echo ""

# Change this to your preferred copyright owner
COPYRIGHT_OWNER="Khallid H Nurse (DBA DoctorMen)"
YEAR="2025"

PRODUCTS_DIR=~/Recon-automation-Bug-bounty-stack/gumroad_products

# ============================================
# Add COPYRIGHT.txt to each product
# ============================================

for product_dir in product_*; do
    if [ -d "$product_dir" ]; then
        echo "📄 Adding COPYRIGHT.txt to $product_dir..."
        
        cat > "$product_dir/COPYRIGHT.txt" << EOF
════════════════════════════════════════════════════════════════
                      COPYRIGHT NOTICE
════════════════════════════════════════════════════════════════

Copyright © $YEAR $COPYRIGHT_OWNER
All Rights Reserved.

This software and associated documentation files (the "Product") 
are proprietary and confidential.

OWNERSHIP:
This Product is owned by and proprietary to $COPYRIGHT_OWNER.
All intellectual property rights, including but not limited to 
copyrights, patents, trademarks, and trade secrets, are reserved.

COMMERCIAL LICENSE:
This Product is licensed, not sold. By purchasing and using this 
Product, you agree to the following terms:

PERMITTED USE:
✅ Use the Product for your own commercial projects
✅ Modify the Product for your own use
✅ Use the Product for client work (unlimited clients)
✅ Create derivative works for your own commercial use

PROHIBITED USE:
❌ Reselling or redistributing the Product as-is
❌ Sharing the Product with others who haven't purchased
❌ Claiming authorship or ownership of the Product
❌ Removing or modifying copyright notices
❌ Reverse engineering for competitive purposes

WARRANTY DISCLAIMER:
This Product is provided "AS IS" without warranty of any kind, 
express or implied, including but not limited to the warranties 
of merchantability, fitness for a particular purpose, and 
non-infringement.

LIMITATION OF LIABILITY:
In no event shall $COPYRIGHT_OWNER be liable for any claim, 
damages, or other liability, whether in an action of contract, 
tort, or otherwise, arising from, out of, or in connection with 
the Product or the use or other dealings in the Product.

ENFORCEMENT:
Unauthorized use, copying, or distribution of this Product 
constitutes copyright infringement and may result in civil and 
criminal penalties, including but not limited to statutory 
damages and attorney's fees.

CONTACT:
For licensing inquiries or questions about permitted use, 
please contact the copyright owner.

════════════════════════════════════════════════════════════════
Copyright © $YEAR $COPYRIGHT_OWNER. All Rights Reserved.
════════════════════════════════════════════════════════════════
EOF
    fi
done

# ============================================
# Add EULA.txt to each product
# ============================================

for product_dir in product_*; do
    if [ -d "$product_dir" ]; then
        echo "📜 Adding EULA.txt to $product_dir..."
        
        cat > "$product_dir/EULA.txt" << EOF
END USER LICENSE AGREEMENT (EULA)

Copyright © $YEAR $COPYRIGHT_OWNER
All Rights Reserved.

This End User License Agreement ("Agreement") is a legal agreement 
between you (the "Licensee") and $COPYRIGHT_OWNER (the "Licensor") 
for the software product and associated materials (the "Product").

BY PURCHASING AND/OR USING THIS PRODUCT, YOU AGREE TO BE BOUND BY 
THE TERMS OF THIS AGREEMENT.

1. GRANT OF LICENSE
The Licensor grants you a non-exclusive, non-transferable license to:
- Use the Product for commercial purposes
- Modify the Product for your own use
- Use the Product for unlimited client projects
- Create derivative works for your commercial use

2. RESTRICTIONS
You may NOT:
- Resell, redistribute, or sublicense the Product as-is
- Share the Product with others who have not purchased it
- Remove or modify copyright notices
- Claim authorship or ownership of the Product
- Use the Product for illegal activities
- Reverse engineer for competitive purposes

3. INTELLECTUAL PROPERTY
The Product is protected by copyright laws and international treaty 
provisions. The Licensor retains all rights, title, and interest in 
and to the Product, including all copyrights, patents, trade secrets, 
trademarks, and other intellectual property rights.

4. UPDATES AND SUPPORT
The Licensor is not obligated to provide updates, bug fixes, or 
technical support. Any updates provided are at the sole discretion 
of the Licensor.

5. TERMINATION
This license is effective until terminated. Your rights under this 
license will terminate automatically without notice if you fail to 
comply with any term of this Agreement. Upon termination, you must 
destroy all copies of the Product.

6. WARRANTY DISCLAIMER
THE PRODUCT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. THE 
LICENSOR DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT 
NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR 
A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

7. LIMITATION OF LIABILITY
IN NO EVENT SHALL THE LICENSOR BE LIABLE FOR ANY SPECIAL, INCIDENTAL, 
INDIRECT, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY 
TO USE THE PRODUCT, EVEN IF THE LICENSOR HAS BEEN ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGES.

8. GOVERNING LAW
This Agreement shall be governed by and construed in accordance with 
the laws of the United States, without regard to its conflict of law 
provisions.

9. ENTIRE AGREEMENT
This Agreement constitutes the entire agreement between you and the 
Licensor concerning the Product and supersedes all prior agreements 
and understandings.

10. CONTACT
For questions about this license, contact: $COPYRIGHT_OWNER

════════════════════════════════════════════════════════════════
By using this Product, you acknowledge that you have read this 
Agreement, understand it, and agree to be bound by its terms.

Copyright © $YEAR $COPYRIGHT_OWNER. All Rights Reserved.
════════════════════════════════════════════════════════════════
EOF
    fi
done

# ============================================
# Update existing LICENSE.txt files
# ============================================

for product_dir in product_*; do
    if [ -d "$product_dir" ]; then
        echo "📋 Updating LICENSE.txt in $product_dir..."
        
        cat > "$product_dir/LICENSE.txt" << EOF
COMMERCIAL USE LICENSE

Copyright © $YEAR $COPYRIGHT_OWNER
All Rights Reserved.

This Product is licensed for commercial use under the following terms:

PERMITTED:
✅ Use for commercial projects
✅ Modification for personal/commercial use
✅ Use for client work (unlimited)
✅ Integration into commercial applications

NOT PERMITTED:
❌ Resale or redistribution as standalone product
❌ Sharing with non-purchasers
❌ Removal of copyright notices

For full terms, see EULA.txt

Copyright © $YEAR $COPYRIGHT_OWNER. All Rights Reserved.
EOF
    fi
done

# ============================================
# Add README with copyright info
# ============================================

for product_dir in product_*; do
    if [ -d "$product_dir" ]; then
        product_name=$(echo $product_dir | sed 's/product_[0-9]_//' | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')
        
        echo "📖 Adding README_COPYRIGHT.txt to $product_dir..."
        
        cat > "$product_dir/README_COPYRIGHT.txt" << EOF
════════════════════════════════════════════════════════════════
                   IMPORTANT: READ THIS FIRST
════════════════════════════════════════════════════════════════

Thank you for purchasing $product_name!

COPYRIGHT PROTECTION:
This product is protected by copyright law. All files and materials 
included are the intellectual property of $COPYRIGHT_OWNER.

COMMERCIAL LICENSE INCLUDED:
You have purchased a commercial license, which means:
✅ You CAN use this for your business
✅ You CAN use this for client projects
✅ You CAN modify it for your needs
✅ You CAN keep all revenue you generate

You CANNOT:
❌ Resell this product
❌ Share with others who haven't purchased
❌ Claim it as your own work

IMPORTANT FILES:
- COPYRIGHT.txt - Full copyright notice
- EULA.txt - End User License Agreement (legal terms)
- LICENSE.txt - Quick licensing summary

By using this product, you agree to these terms.

Questions? The copyright owner can be reached via Gumroad message.

════════════════════════════════════════════════════════════════
Copyright © $YEAR $COPYRIGHT_OWNER. All Rights Reserved.
════════════════════════════════════════════════════════════════
EOF
    fi
done

# ============================================
# Re-zip all products with new copyright files
# ============================================

echo ""
echo "📦 Re-packaging all products with copyright protection..."
echo ""

# Remove old ZIPs
rm -f *.zip

# Create new ZIPs
zip -r Security_Automation_Toolkit.zip product_1_security_toolkit/
zip -r Upwork_Freelancing_System.zip product_2_upwork_system/
zip -r Bug_Bounty_Starter_Pack.zip product_3_bug_bounty_pack/
zip -r Divergent_Thinking_System.zip product_4_divergent_thinking/
zip -r Complete_Business_Bundle.zip product_5_business_bundle/

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ COPYRIGHT PROTECTION ADDED TO ALL PRODUCTS!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📄 Each product now includes:"
echo "  - COPYRIGHT.txt (comprehensive copyright notice)"
echo "  - EULA.txt (End User License Agreement)"
echo "  - LICENSE.txt (commercial use license)"
echo "  - README_COPYRIGHT.txt (buyer instructions)"
echo ""
echo "🔒 All products are now fully copyright protected."
echo ""
echo "📦 Updated ZIP files:"
ls -lh *.zip
echo ""
echo "🚀 Ready to upload to Gumroad with full legal protection!"
echo ""
echo "════════════════════════════════════════════════════════════════"
