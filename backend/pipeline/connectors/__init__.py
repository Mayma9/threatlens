"""One connector per CTI source, all implementing BaseConnector.

REGISTRY order = execution order: the CWE catalog first (CVE records link to it), then the
CVE records (the reference list), then the sources that enrich them (NVD, KEV, EPSS),
then ThreatFox (indicators of compromise, independent of the CVEs).
"""

from .cve_list_v5 import CveListV5Connector
from .cwe import CweConnector
from .epss import EpssConnector
from .kev import KevConnector
from .nvd import NvdConnector
from .threatfox import ThreatFoxConnector

REGISTRY = {
    CweConnector.name: CweConnector,
    CveListV5Connector.name: CveListV5Connector,
    NvdConnector.name: NvdConnector,
    KevConnector.name: KevConnector,
    EpssConnector.name: EpssConnector,
    ThreatFoxConnector.name: ThreatFoxConnector,
}
