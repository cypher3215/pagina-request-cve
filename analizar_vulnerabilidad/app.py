import requests

def get_cve_info(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cveId": cve_id  # Filtro para el CVE
    }

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            # Verificamos si hay datos en la respuesta
            if "vulnerabilities" in data and data["vulnerabilities"]:
                vuln_data = data["vulnerabilities"][0]
                
                cvss = vuln_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                description = vuln_data.get("cve", {}).get("descriptions", [{}])[0].get("value", "No encontrado")
                return {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss.get("baseScore", "No encontrado"),
                    "cvss_version": cvss.get("version", "No encontrado")
                }
            else:
                return {"error": "No se encontraron datos para este CVE"}
        else:
            return {"error": f"Error en la solicitud: C贸digo {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Error de conexi贸n: {e}"}

cve_id = input("CVE : ")
cve_info = get_cve_info(cve_id)
if "error" not in cve_info:
    print(f"CVE ID: {cve_info['cve_id']}")
    print(f"Descripci贸n: {cve_info['description']}")
    print(f"CVSS Score: {cve_info['cvss_score']}")
    print(f"Versi贸n CVSS: {cve_info['cvss_version']}")
else:
    print(cve_info["error"])
