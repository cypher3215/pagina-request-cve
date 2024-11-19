import requests
from bs4 import BeautifulSoup

def get_cve_info(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            # Parseamos el contenido de la página
            soup = BeautifulSoup(response.content, "html.parser")

            # Imprimir el HTML para depuración si es necesario
            # print(soup.prettify())

            # Buscar la información del CVSS (puede estar en un <pre> dentro de un <td>)
            cvss_score_cell = soup.find("td", {"data-testid": "vuln-change-history-45-new"})
            if cvss_score_cell:
                cvss_score = cvss_score_cell.get_text(strip=True)
            else:
                cvss_score = "No encontrado"

            # Buscar el tipo de CVSS (por ejemplo, V3.1)
            cvss_type_cell = soup.find("td", {"data-testid": "vuln-change-history-45-type"})
            if cvss_type_cell:
                cvss_type = cvss_type_cell.get_text(strip=True)
            else:
                cvss_type = "No encontrado"

            # También podemos buscar una breve descripción si está disponible
            description = soup.find("p", {"class": "vuln-description"})
            if description:
                description_text = description.get_text(strip=True)
            else:
                description_text = "No encontrado"

            # Devolvemos la información encontrada
            return {
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'cvss_type': cvss_type,
                'description': description_text
            }

        else:
            print(f"Error: No se pudo acceder a la página. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")
        return None

# Ejemplo de uso con una CVE específica
cve_info = get_cve_info("CVE-2023-48795")
if cve_info:
    print(f"CVE ID: {cve_info['cve_id']}")
    print(f"CVSS Score: {cve_info['cvss_score']}")
    print(f"CVSS Type: {cve_info['cvss_type']}")
    print(f"Description: {cve_info['description']}")
else:
    print("No se encontraron datos para la CVE.")
