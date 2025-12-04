# pricing_plans.py
PACKAGES = {
    "Starter": {
        "price": 99,
        "features": ["Basic API Access", "Documentation", "Email Support"],
        "automation": "Basic security scans"
    },
    "Professional": {
        "price": 499,
        "features": ["Full API Access", "Custom Scripts", "Priority Support"],
        "automation": "Advanced security automation"
    }
}

# Example usage
if __name__ == "__main__":
    for package, details in PACKAGES.items():
        print(f"\n{package} (${details['price']}/month):")
        print("Features:", ", ".join(details["features"]))
        print("Automation:", details["automation"])
