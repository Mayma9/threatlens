"""One connector per CTI source, all implementing BaseConnector.

REGISTRY order = execution order: CVE records first, then the sources that refer to them.
"""

from .cve_list_v5 import CveListV5Connector

REGISTRY = {
    CveListV5Connector.name: CveListV5Connector,
}
