"""
Script to retrieve CVEs and Security Issues from a Cyberwatch instance
based on a specified group.
Author: Amine Hazi 
"""

import json
import logging
import requests
from tqdm import tqdm
from cyberwatch_api import Cyberwatch_Pyhelper

# Set up logging
logging.basicConfig(level=logging.INFO)

assets_of_group = []


def get_group_id(group_name):
    """
    Retrieve the group ID from Cyberwatch API by the provided group name.
    Returns the group ID if found, otherwise None.
    """
    all_groups = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                # Use an f-string so {page} is actually replaced by page.
                endpoint=f"/api/v3/groups?page={page}",
                params={'page': page},
            )
            response_data = next(response).json()

            logging.info("Getting groups from page %s. First group ID: %s",
                         page, response_data[0]['id'])

            all_groups.extend(response_data)

            # If we got fewer than 100 items, we assume we reached the last page
            if len(response_data) < 100:
                break

            page += 1

        except requests.exceptions.RequestException as exc:
            logging.error("Error while getting Cyberwatch groups: %s", exc)
            break

    for group in all_groups:
        if group['name'].lower() == group_name.lower():
            return group['id']
    return None


def get_assets_of_group(group_id):
    """
    Retrieve the list of assets (servers) for a given group ID and
    store them in 'assets.json'.
    """
    all_assets = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint=f"/api/v3/servers?group_id={group_id}&page={page}",
                params={'page': page, 'group_id': group_id},
            )
            response_data = next(response).json()

            logging.info("Getting assets from page %s. First asset ID: %s",
                         page, response_data[0]['id'])

            all_assets.extend(response_data)

            if len(response_data) < 100:
                break

            page += 1

        except requests.exceptions.RequestException as exc:
            logging.error("Error while getting cyberwatch assets: %s", exc)
            break

    with open("assets.json", "w", encoding="utf-8") as file_out:
        file_out.write(json.dumps(all_assets))

    return all_assets


def get_cves(group):
    """
    Retrieve a list of CVE announcements for the given group name.
    """
    all_cves = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint=f"/api/v3/cve_announcements?groups[]={group}&page={page}",
                params={'page': page, 'group': group},
            )
            response_data = next(response).json()

            logging.info("Getting CVEs from page %s. First CVE: %s",
                         page, response_data[0]['cve_code'])

            all_cves.extend(response_data)

            if len(response_data) < 100:
                break

            page += 1

        except requests.exceptions.RequestException as exc:
            logging.error("Error while getting cyberwatch cves: %s", exc)
            break

    return all_cves


def forge_cve_json_line(cve, output_file):
    """
    Forge a single CVE JSON line and append it to the specified output_file.
    """
    with open(output_file, 'a', encoding="utf-8") as file_out:
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
            # Only include servers that are in assets_of_group
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
                product_name = None
                version = None
                if update['current']:
                    product_name = update['current']['product']
                    version = update['current']['version']
                elif update['target']:
                    product_name = update['target']['product']
                    version = update['target']['version']

                if product_name:
                    # Add to server updates
                    server_info["updates"].append({
                        "product": product_name,
                        "version": version
                    })

                    # Normalize product name to lowercase
                    normalized_product = product_name.lower()

                    if normalized_product not in products_dict:
                        products_dict[normalized_product] = {
                            "assets": set(),
                            "versions": set()
                        }

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
        file_out.write(json.dumps(cve_json_line) + '\n')
        file_out.flush()


def get_all_cves_details(group, output_file):
    """
    Retrieve all CVEs for the given group, fetch their details,
    and write them to the specified output file.
    """
    logging.info("--------------- Getting all CVEs ---------------")
    cves = get_cves(group)
    total_cves = len(cves)
    logging.info("--------------- Number of CVEs: %s ---------------", total_cves)
    logging.info("--------------- Getting CVE details ---------------")

    cves_details = []
    progress_bar = tqdm(total=total_cves, desc="Processing CVEs",
                        unit="CVE", dynamic_ncols=True)

    for cve in cves:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint=f"/api/v3/cve_announcements/{cve['cve_code']}",
                params={'cve_id': cve['cve_code']},
            )
            logging.info("Getting CVE details for %s", cve['cve_code'])
            response_data = next(response).json()
            forge_cve_json_line(response_data, output_file)
            cves_details.append(response_data)
        except requests.exceptions.RequestException as exc:
            logging.error("Error while getting Cyberwatch CVE details: %s", exc)
        progress_bar.update(1)

    progress_bar.close()
    return cves_details


def get_security_issues():
    """
    Retrieve all security issues from Cyberwatch.
    """
    all_security_issues = []
    page = 1
    while True:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint=f"/api/v3/security_issues?page={page}",
            )
            response_data = next(response).json()

            logging.info("Getting security issues from page %s. First security issue ID: %s",
                         page, response_data[0]['id'])

            all_security_issues.extend(response_data)

            if len(response_data) < 100:
                break

            page += 1

        except requests.exceptions.RequestException as exc:
            logging.error("Error while getting cyberwatch security issues: %s", exc)
            break

    return all_security_issues


def forge_security_issue_json_line(security_issue, output_file):
    """
    Forge a single Security Issue JSON line and append it to output_file,
    but only if it has servers that belong to assets_of_group.
    """
    relevant_servers = []
    for server in security_issue['servers']:
        for asset in assets_of_group:
            if server['id'] == asset['id']:
                relevant_servers.append(server)
    if not relevant_servers:
        return

    with open(output_file, 'a', encoding="utf-8") as file_out:
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
        file_out.write(json.dumps(security_issue_json_line) + '\n')
        file_out.flush()


def get_all_security_issues_details(output_file):
    """
    Retrieve all security issues and write their details to the output file.
    """
    logging.info("--------------- Getting all Security Issues ---------------")
    security_issues = get_security_issues()
    total_security_issues = len(security_issues)
    logging.info("--------------- Number of Security Issues: %s ---------------",
                 total_security_issues)
    logging.info("--------------- Getting Security Issues details ---------------")

    security_issues_details = []
    progress_bar = tqdm(total=total_security_issues, desc="Processing Security Issues",
                        unit="Security Issue")

    for security_issue in security_issues:
        try:
            response = Cyberwatch_Pyhelper().request(
                method="get",
                endpoint=f"/api/v3/security_issues/{security_issue['id']}",
                params={'id': security_issue['id']},
            )
            logging.info("Getting Security Issue details for %s", security_issue['id'])
            response_data = next(response).json()
            forge_security_issue_json_line(response_data, output_file)
            security_issues_details.append(response_data)
        except requests.exceptions.RequestException as exc:
            logging.error("Error while getting Cyberwatch Security Issue details: %s", exc)
            break
        finally:
            progress_bar.update(1)

    progress_bar.close()
    return security_issues_details


def main():
    """
    Main function: prompts the user for a group name,
    retrieves assets, CVEs, and Security Issues, then writes them to a file.
    """
    group = input("Enter the group name: ")
    group_id = get_group_id(group)

    if not group_id:
        logging.error("Group '%s' not found", group)
        return

    logging.info("Group id: %s", group_id)

    global assets_of_group  # pylint: disable=global-statement
    assets_of_group = get_assets_of_group(group_id)

    output_file = f"Cyberwatch_scan_{group}.json"

    get_all_cves_details(group, output_file)
    get_all_security_issues_details(output_file)


if __name__ == "__main__":
    main()
