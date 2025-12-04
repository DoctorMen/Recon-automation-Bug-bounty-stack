import openai

# Set your OpenAI API key
openai.api_key = "YOUR_API_KEY"

# Function to generate a report using GPT-4
def generate_report(scan_data):
    prompt = f"Generate a detailed vulnerability report for the following scan data: {scan_data}"
    response = openai.Completion.create(
        engine="gpt-4",
        prompt=prompt,
        max_tokens=500
    )
    return response.choices[0].text.strip()

# Example usage
if __name__ == "__main__":
    scan_data = "Target: example.com, Vulnerabilities: XSS, SQL Injection, Severity: High"
    report = generate_report(scan_data)
    print("Generated Report:\n", report)
