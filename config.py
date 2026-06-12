DAYS_BACK = 7

REFRESH_INTERVAL_MINUTES = 5

# SentinelOne
MSSP_ALLOWED_CLIENTS = [
    "QuisLex",
    "CapLaw",
    "LegalOps",
    "LCRA",
    "Consint.ai",
    "NopalCyber"
]
# excluding greenko edr because we dont manage edr for them
RESSELLER_EXCLUDED_CLIENTS = [
    "Greenko-Energy-EDR"
]

MANAGED_CLIENTS = {
    "sentinelone": {
        "QuisLex": ["mssp"],
        "CapLaw": ["mssp"],
        "LegalOps": ["mssp"],
        "LCRA": ["mssp"],
        "Consint.ai": ["mssp"],
        "NopalCyber": ["mssp"],
        "Heritage Foods": ["reseller"],
        "AM Green Ammonia Pvt Ltd": ["reseller"],
        "HEALTHNET GLOBAL LIMITED": ["reseller"],
        "STAR HOSPITALS": ["reseller"],
        "Sudhakar PVC products pvt ltd": ["reseller"],
        "Greenko Energy Projects Private Limited": ["reseller"],
        "Health Axis Private Ltd": ["reseller"],
        "Progility Technologies Pvt. Ltd.": ["reseller"],
        "Mythri Hospital": ["reseller"],
        "Revalsys Technologies PVT LTD": ["reseller"]
    }
}

SENTINELONE_SOURCES = [
    {
        "name": "mssp",
        "url": (
            "https://usea1-002-mssp.sentinelone.net/web/api/v2.1/threats"
        ),
        "token_env": "S1_MSSP_API_TOKEN",
        "filter_clients": True
    },
    {
        "name": "reseller",
        "url": (
            "https://apso1-1003.sentinelone.net/web/api/v2.1/threats"
        ),
        "token_env": "S1_RESELLER_API_TOKEN",
        "filter_clients": False
    }
]

# Wazuh
WAZUH_URL = (
    "https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts"
)

WAZUH_MIN_RULE_LEVEL = 5

WAZUH_HOURS = 24

WAZUH_LIMIT = 500

WAZUH_VERIFY_SSL = False

WAZUH_ALLOWED_CLIENTS = [
    "Progility",
    "NCC",
    "Rainbow Hospitals"
]

WAZUH_CLIENT_MAPPING = {
    "Progility": "Progility",
    "NCC": "NCC-Bihar",
    "Rainbow Hospitals":
        "Rainbow_Children_Hospitals"
}

# JIRA
JIRA_URL = (
    "https://nopalcyber.atlassian.net/rest/api/3/search/jql"
)
