"""One connector per CTI source, all implementing BaseConnector.

REGISTRY order = execution order: the CWE catalog first (CVE records link to it), then the
CVE records, then the sources that refer to them.
"""

from .cve_list_v5 import CveListV5Connector
from .cwe import CweConnector
from .epss import EpssConnector
from .kev import KevConnector

REGISTRY = {
    CweConnector.name: CweConnector,
    CveListV5Connector.name: CveListV5Connector,
    KevConnector.name: KevConnector,
    EpssConnector.name: EpssConnector,
}
