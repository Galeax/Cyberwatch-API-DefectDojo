import requests
from tqdm import tqdm
import json
from cyberwatch_api import Cyberwatch_Pyhelper
import logging 

# Set up logging
logging.basicConfig(level=logging.INFO)

assets_of_group = []

def get_group_id(group_name):
    all_groups = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint="/api/v3/groups?page={page}",
                params={'page': page},
            )
            response_data = next(response).json()
            if len(response_data) < 100:
                logging.info(f"Getting groups from page {page} first group : {response_data[0]['id']}")
                all_groups.extend(response_data)
                break
            logging.info(f"Getting groups from page {page} first group : {response_data[0]['id']}")
            all_groups.extend(response_data)
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while getting cyberwatch groups : {e}")
            break
    for group in all_groups:
        if group['name'].lower() == group_name.lower():
            return group['id']
    return None

def get_assets_of_group(group_id):
    all_assets = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint="/api/v3/servers?group_id={group_id}&page={page}",
                params={'page': page, 'group_id': group_id},
            )
            response_data = next(response).json()
            if len(response_data) < 100:
                logging.info(f"Getting assets from page {page} first asset : {response_data[0]['id']}")
                all_assets.extend(response_data)
                break
            logging.info(f"Getting assets from page {page} first asset : {response_data[0]['id']}")
            all_assets.extend(response_data)
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while getting cyberwatch assets : {e}")
            break
    with open("assets.json", "w") as f:
        f.write(json.dumps(all_assets))
    return all_assets

# Get all cves from Cyberwatch api 
def get_cves(group):
    all_cves = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint="/api/v3/cve_announcements?groups[]={group}&page={page}",
                params={'page': page, 'group': group},
            )
            response_data = next(response).json()
            if len(response_data) < 100:
                logging.info(f"Getting cves from page {page} first cve : {response_data[0]['cve_code']}")
                all_cves.extend(response_data)
                break
            logging.info(f"Getting cves from page {page} first cve : {response_data[0]['cve_code']}")
            all_cves.extend(response_data)
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while getting cyberwatch cves : {e}")
            break
    return all_cves

# Get all cves details from Cyberwatch api
def get_all_cves_details(group, output_file):
    logging.info("--------------- Getting all CVEs ---------------")
    cves = get_cves(group)
    total_cves = len(cves)
    logging.info(f"--------------- Number of CVEs: {total_cves} ---------------")
    logging.info("--------------- Getting CVE details ---------------")
    
    cves_details = []
    progress_bar = tqdm(total=total_cves, desc="Processing CVEs", unit="CVE", dynamic_ncols=True)
    
    for cve in cves:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint="/api/v3/cve_announcements/{cve_id}",
                params={'cve_id': cve['cve_code']},
            )
            logging.info(f"Getting CVE details for {cve['cve_code']}")
            response_data = next(response).json()
            forge_cve_json_line(response_data, output_file)
            cves_details.append(response_data)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while getting Cyberwatch CVE details: {e}")
        progress_bar.update(1)
    
    progress_bar.close()
    return cves_details

import json

def forge_cve_json_line(cve, output_file):
    with open(output_file, 'a') as f:
        cve_json_line = {
            "type": "CVE",
            "cve_code": cve['cve_code'],
            "cve_score": cve['score'],
            "cve_level": cve['level'],
            "cve_published_at": cve['published'],
            "updated_at": cve['last_modified'],
            "exploit_code_maturity": cve['exploit_code_maturity'],
            "cve_epss": cve['epss'],
            "cvss_v3": cve['cvss_v3'],
            "cwes": cve['cwe'],
            "servers": []
        }

        # Dictionary to track product data: product -> { "assets": set(), "versions": set() }
        products_dict = {}

        for server in cve['servers']:
            if server['id'] not in [asset['id'] for asset in assets_of_group]:
                continue
            
            server_info = {
                "active": server['active'],
                "fixed_at": server['fixed_at'],
                "ignored": server['ignored'],
                "computer_environment": server['environmental_score'],
                "computer_id": server['id'],
                "computer_name": server['hostname'],
                "computer_os": server['os']['key'],
                "computer_os_name": server['os']['name'],
                "computer_os_arch": server['os']['arch'],
                "updates": []
            }

            for update in server['updates']:
                product_name = update['current']['product'] if update['current'] else (update['target']['product'] if update['target'] else None)
                version = update['current']['version'] if update['current'] else (update['target']['version'] if update['target'] else None)

                if product_name:
                    # Add to server updates
                    server_info["updates"].append({
                        "product": product_name,
                        "version": version
                    })

                    # Normalize product name to lowercase to keep consistency
                    normalized_product = product_name.lower()
                    if normalized_product not in products_dict:
                        products_dict[normalized_product] = {
                            "assets": set(),
                            "versions": set()
                        }

                    # Add the server and version to the product data
                    products_dict[normalized_product]["assets"].add(server['hostname'])
                    if version:
                        products_dict[normalized_product]["versions"].add(version)

            cve_json_line["servers"].append(server_info)

        # Convert sets to lists for JSON serialization
        updates_assets = {}
        for product, data in products_dict.items():
            updates_assets[product] = {
                "assets": list(data["assets"]),
                "versions": list(data["versions"])
            }

        # Add updates_assets field
        cve_json_line["updates_assets"] = updates_assets

        # Write the line
        f.write(json.dumps(cve_json_line) + '\n')
        f.flush()
 
         
# Get all security issues from Cyberwatch api
def get_security_issues():
    all_security_issues = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint="/api/v3/security_issues",
            )
            response_data = next(response).json()
            if len(response_data) < 100:
                logging.info(f"Getting security issues from page {page} first security issue : {response_data[0]['id']}")
                all_security_issues.extend(response_data)
                break
            logging.info(f"Getting security issues from page {page} first security issue : {response_data[0]['id']}")
            all_security_issues.extend(response_data)
            page += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while getting cyberwatch security issues : {e}")
            break
    return all_security_issues

# Get all security issues details from Cyberwatch api
def get_all_security_issues_details(output_file):
    logging.info("--------------- Getting all Security Issues ---------------")
    security_issues = get_security_issues()
    total_security_issues = len(security_issues)
    logging.info(f"--------------- Number of Security Issues: {total_security_issues} ---------------")
    logging.info("--------------- Getting Security Issues details ---------------")
    
    security_issues_details = []
    progress_bar = tqdm(total=total_security_issues, desc="Processing Security Issues", unit="Security Issue")
    
    for security_issue in security_issues:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint="/api/v3/security_issues/{id}",
                params={'id': security_issue['id']},
            )
            logging.info(f"Getting Security Issue details for {security_issue['id']}")
            response_data = next(response).json()
            forge_security_issue_json_line(response_data, output_file)
            security_issues_details.append(response_data)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while getting Cyberwatch Security Issue details: {e}")
            break
        finally:
            progress_bar.update(1)
    
    progress_bar.close()
    return security_issues_details

# forge security issue json line
def forge_security_issue_json_line(security_issue, output_file):
    relevant_servers = []
    for server in security_issue['servers']:
        for asset in assets_of_group:
            if server['id'] == asset['id']:
                relevant_servers.append(server)
    if not relevant_servers:
        return

    with open(output_file, 'a') as f:
        security_issue_json_line = {
            "type": "Security Issue",
            "id": security_issue['id'],
            "security_issue_id": security_issue['sid'],
            "level": security_issue['level'],
            "editable": security_issue['editable'],
            "security_issue_title": security_issue['title'],
            "security_issue_description": security_issue['description'],
            "servers": [],
            "cve_announcements": security_issue['cve_announcements']
        }
        for server in relevant_servers:
            server_info = {
                "active": server['status'],
                "computer_id": server['id'],
                "computer_name": server['hostname'],
                "detected_at": server['detected_at']
            }
            security_issue_json_line["servers"].append(server_info)
        f.write(json.dumps(security_issue_json_line) + '\n')
        f.flush()


# main function
def main():
    
    group = input("Enter the group name: ")
    group_id = get_group_id(group)
    global assets_of_group
    assets_of_group = get_assets_of_group(group_id)

    if not group_id:
        logging.error("Group not found")
        return
    logging.info(f"Group id: {group_id}")
    
    output_file = f"Cyberwatch_scan_{group}.json"
    
    get_all_cves_details(group, output_file)
    get_all_security_issues_details(output_file)
        
if __name__ == "__main__":
    main()

