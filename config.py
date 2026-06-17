REFRESH_INTERVAL_MINUTES = 5

# SentinelOne
SENTINELONE_ALERT_WINDOW_HOURS = 24

SENTINELONE_JIRA_WINDOW_HOURS = 24

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
    },
    "securonix": {
        "QuisLex": ["securonix"],
        "NopalCyber": ["securonix"]
    }
}

SENTINELONE_CLIENT_MAPPING = {
    "AM Green":
        "AM Green Ammonia Pvt Ltd",
    "HNG":
        "HEALTHNET GLOBAL LIMITED",
    "Sudhakar_PVC":
        "Sudhakar PVC products pvt ltd",
    "Progility":
        "Progility Technologies Pvt. Ltd.",
    "STAR_NRG":
        "STAR HOSPITALS",
    "STAR_Banjara":
        "STAR HOSPITALS",
    "Greenko-Energy-MDR":
        "Greenko Energy Projects Private Limited"
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
WAZUH_ALERT_WINDOW_HOURS = 24

WAZUH_JIRA_WINDOW_HOURS = 24

WAZUH_URL = (
    "https://whb.nopalcyber.com/api/v1/integrations/wazuh-alert-counts"
)

WAZUH_MIN_RULE_LEVEL = 5

WAZUH_HOURS = WAZUH_ALERT_WINDOW_HOURS

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

WAZUH_JIRA_CLIENT_HINTS = {
    "Rainbow_Children_Hospitals": [
        "Rainbow-NC-VCiso",
        "RAINBOWHOSPITAL",
        "RCH"
    ],
    "NCC-Bihar": [
        "NCC"
    ],
    "Progility": [
        "Progility"
    ]
}

# JIRA
JIRA_URL = (
    "https://nopalcyber.atlassian.net/rest/api/3/search/jql"
)

WAZUH_JIRA_TENANT_FIELD = "customfield_10202"

# Securonix
SECURONIX_INCIDENT_WINDOW_HOURS = 24

SECURONIX_JIRA_WINDOW_HOURS = 24

SECURONIX_ALLOWED_CLIENTS = [
    "QuisLex",
    "NopalCyber"
]

SECURONIX_CLIENT_MAPPING = {
    "Nopal Cyber": "NopalCyber"
}

SECURONIX_INCIDENT_PAGE_SIZE = 100

SECURONIX_VERIFY_SSL = True

SECURONIX_JIRA_TENANT_FIELD = WAZUH_JIRA_TENANT_FIELD
