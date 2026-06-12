import requests
from datetime import datetime, timedelta
from utils.cwe_mapper import map_cwe


def get_latest_cves():

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 1000
    }

    try:
        response = requests.get(url, params=params, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()

        results = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            severity = "Unknown"
            score = 0

            metrics = cve.get("metrics", {})

            if metrics.get("cvssMetricV31"):
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "Unknown")
                score = cvss.get("baseScore", 0)

            elif metrics.get("cvssMetricV30"):
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "Unknown")
                score = cvss.get("baseScore", 0)

            elif metrics.get("cvssMetricV2"):
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                severity = metrics["cvssMetricV2"][0].get(
                    "baseSeverity",
                    "Unknown"
                )
                score = cvss.get("baseScore", 0)

            descriptions = cve.get("descriptions", [])

            description = ""

            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # تجاهل الثغرات الضعيفة
            if score < 7:
                continue

            weaknesses = cve.get("weaknesses", [])

            cwe_id = "Unknown"

            if weaknesses:

                descriptions = weaknesses[0].get(
                    "description",
                    []
                )

                if descriptions:
                    cwe_id = descriptions[0].get(
                        "value",
                        "Unknown"
                    )

            category = map_cwe(cwe_id)

            results.append({
                "id": cve.get("id"),
                "severity": severity,
                "score": score,
                "cwe": cwe_id,
                "category": category,
                "published": cve.get("published"),
                "description": description
            })
            

        # ترتيب حسب الخطورة
        results.sort(
            key=lambda x: x["score"],
            reverse=True
        )

        return results[:20]

    except Exception as e:
        print("NVD ERROR:", e)
        return []