import enum


class AnalyticsType(enum.Enum):
    TTP = 1
    anomaly = 2
    hunting = 3
    correlation = 4

class DataModel(enum.Enum):
    Endpoint = 1
    Network_Traffic = 2
    Authentication = 3
    Change = 4
    Change_Analysis = 5
    Email = 6
    Network_Resolution = 7
    Network_Sessions = 8
    UEBA = 9
    Updates = 10
    Vulnerabilities = 11
    Web = 12
    Endpoint_Processes = 13
    Endpoint_Filesystem = 14
    Endpoint_Registry = 15
    Risk = 16

class SecurityContentType(enum.Enum):
    detections = 1
    baselines = 2
    stories = 3
    playbooks = 4
    macros = 5
    lookups = 6
    deployments = 7
    investigations = 8
    unit_tests = 9

class SecurityContentProduct(enum.Enum):
    ESCU = 1
    SSA = 2
    API = 3