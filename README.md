# Cyberwatch-API-DefectDojo
Cyberwatch API script to generate data for DefectDojo parser

## Prerequisites

- Python3
- Access to a Cyberwatch API

## Configure your API access

Create an `api.conf` file with your connection information to Cyberwatch.

Check the Cyberwatch documentation on how to get your API credentials if needed.

## How to use the script

1. Create a virtual env and activate it:

```sh
python3 -m venv .venv
source .venv/bin/activate
```

1. Install the required python packages:

```sh
pip install -r requirements.txt
```

1. Run the script, by default the script will prompt the user to input a group name from Cyberwatch:

```sh
python3 get_cves_security_issues.py
Enter the group name:
```

The script will generate a JSON file that contains all CVEs and security issues (active and inactive) present on the assets that belong to the provided group in Cyberwatch.
