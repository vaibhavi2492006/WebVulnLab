
from scanner import scan_security_headers

# Test against a website you own or are authorized to assess.
url = input("Enter your authorized test website URL (https://...): ").strip()

if not url.startswith(("https://", "http://")):
    print("Please enter a URL starting with https:// or http://")
else:
    result = scan_security_headers(url)

    if result["success"]:
        print("\nWebsite:", result["url"])
        print("HTTP Status:", result["http_status"])
        print("\n--- Security Header Results ---")

        for item in result["results"]:
            print(f"\nHeader: {item['header']}")
            print(f"Status: {item['status']}")
            print(f"Details: {item['details']}")
    else:
        print("\nScan failed:", result["error"])
