from langchain import LangChain

# Initialize LangChain
langchain = LangChain(api_key="YOUR_LANGCHAIN_API_KEY")

# Function to query scan results conversationally
def query_scan_results(query):
    response = langchain.query(query)
    return response

# Example usage
if __name__ == "__main__":
    query = "What vulnerabilities were found in the latest scan?"
    response = query_scan_results(query)
    print("LangChain Response:\n", response)
