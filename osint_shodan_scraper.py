import requests

API_KEY = "YOUR_SHODAN_API_KEY"
query = "apache"
url = f"https://api.shodan.io/shodan/host/search?key={API_KEY}&query={query}"

def shodan_search():
    response = requests.get(url)
    if response.status_code == 200:
        results = response.json()
        for match in results["matches"][:5]:
            print(f"IP: {match['ip_str']} | Org: {match.get('org')} | Port: {match['port']}")
    else:
        print("Error fetching data:", response.status_code)

if __name__ == "__main__":
    shodan_search()