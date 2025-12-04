import stripe

# Set your Stripe API key
stripe.api_key = "YOUR_STRIPE_API_KEY"

# Function to create a new subscription
def create_subscription(customer_id, price_id):
    try:
        subscription = stripe.Subscription.create(
            customer=customer_id,
            items=[{'price': price_id}],
        )
        return subscription
    except stripe.error.StripeError as e:
        print(f"Stripe error: {e}")
        return None

# Example usage
if __name__ == "__main__":
    customer_id = "cus_123456789"
    price_id = "price_123456789"
    subscription = create_subscription(customer_id, price_id)
    if subscription:
        print("Subscription created:", subscription.id)
