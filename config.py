DAYS_BACK = 7

REFRESH_INTERVAL_MINUTES = 5

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

JIRA_URL = (
    "https://nopalcyber.atlassian.net/rest/api/3/search/jql"
)