import sys

try:
    with open("output/tonight_expanded/js_intel_summary.txt", "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if "/internal" in line:
            # Print the 5 lines before it to see the filename
            start = max(0, i - 5)
            print("".join(lines[start:i+1]))
            print("-" * 20)
except Exception as e:
    print(e)
