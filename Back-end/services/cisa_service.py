import requests


def get_exploited_vulnerabilities():

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()

        results = []

        for item in data.get("vulnerabilities", [])[:20]:

            results.append({
                "cve_id": item.get("cveID"),
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "date_added": item.get("dateAdded"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate")
            })

        return results

    except Exception as e:
        print("CISA ERROR:", e)
        return []