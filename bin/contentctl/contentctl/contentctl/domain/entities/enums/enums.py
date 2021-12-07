import enum


class AnalyticsType(enum.Enum):
    TTP = 1
    anomaly = 2
    hunting = 3
    baseline = 4
    investigation = 5
    correlation = 6

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

class SecurityContentType(enum.Enum):
    detections = 1
    stories = 2
    playbooks = 3
    macros = 4
    lookups = 5
    deployments = 6