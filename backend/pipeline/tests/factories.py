"""Small CVE JSON 5.x documents, KEV catalogs and CWE catalogs for tests (no network)."""

import io
import json
import zipfile
from pathlib import Path


def cve_doc(cve_id, *, state="PUBLISHED", published="2024-03-01T10:00:00.000Z", updated="2024-03-02T10:00:00.000Z",
            description="Buffer overflow in the web interface allows remote code execution.",
            cna_score=9.8, adp_score=None, affected=(("Fortinet", "FortiOS", "7.2.0"),),
            cna_cwes=(), adp_cwes=()):
    cna = {
        "descriptions": [{"lang": "en", "value": description}] if description else [],
        "affected": [
            {"vendor": v, "product": p, "versions": [{"version": ver, "status": "affected"}]} for v, p, ver in affected
        ],
        "metrics": [],
    }
    if cna_cwes:
        cna["problemTypes"] = [{"descriptions": [
            {"lang": "en", "type": "CWE", "cweId": cwe, "description": f"{cwe} weakness"} for cwe in cna_cwes
        ] + [{"lang": "en", "type": "text", "description": "Improper input validation"}]}]  # free text, no cweId
    if cna_score is not None:
        cna["metrics"].append({"cvssV3_1": {"version": "3.1", "baseScore": cna_score, "baseSeverity": "CRITICAL",
                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
    containers = {"cna": cna}
    if adp_score is not None or adp_cwes:
        containers["adp"] = [{
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": ([
                {"cvssV3_1": {"version": "3.1", "baseScore": adp_score, "baseSeverity": "HIGH",
                              "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
                {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}]}}},
            ] if adp_score is not None else []),
            "problemTypes": [{"descriptions": [
                {"lang": "en", "type": "CWE", "cweId": cwe, "description": cwe} for cwe in adp_cwes
            ]}],
        }]
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": state, "datePublished": published, "dateUpdated": updated},
        "containers": containers,
    }


def write_bulk_zip(path: Path, docs) -> Path:
    """Same layout as the GitHub release file: a zip containing cves.zip, containing cves/<year>/<xxx>/<id>.json."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        for doc in docs:
            cve_id = doc["cveMetadata"]["cveId"]
            year = cve_id.split("-")[1] if cve_id.count("-") == 2 else "0000"
            z.writestr(f"cves/{year}/1xxx/{cve_id or 'bad'}.json", json.dumps(doc))
        z.writestr("cves/delta.json", "{}")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("cves.zip", inner.getvalue())
    return path


def write_kev_json(path: Path, entries) -> Path:
    path.write_text(json.dumps({
        "catalogVersion": "2026.10.20", "count": len(entries),
        "vulnerabilities": [
            {"cveID": cve, "dateAdded": added, "dueDate": "2026-11-10", "requiredAction": "Apply updates.",
             "knownRansomwareCampaignUse": ransom}
            for cve, added, ransom in entries
        ],
    }), encoding="utf-8")
    return path


def write_cwe_zip(path: Path, weaknesses=(), categories=(), version="4.16", day="2024-11-19") -> Path:
    """Same layout as cwec_latest.xml.zip: one XML file, namespace cwe-7, with weaknesses, categories and a view.

    weaknesses: (id, name, abstraction, status); categories: (id, name, status).
    """
    ns = "http://cwe.mitre.org/cwe-7"
    weakness_xml = "".join(
        f'<Weakness ID="{i}" Name="{n}" Abstraction="{a}" Structure="Simple" Status="{s}">'
        f"<Description>{n}.</Description>"
        f'<Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000"/></Related_Weaknesses>'
        f"</Weakness>"
        for i, n, a, s in weaknesses
    )
    category_xml = "".join(
        f'<Category ID="{i}" Name="{n}" Status="{s}"><Summary>{n}.</Summary>'
        f'<Relationships><Has_Member CWE_ID="79" View_ID="699"/></Relationships></Category>'
        for i, n, s in categories
    )
    xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<Weakness_Catalog xmlns="{ns}" Name="CWE" Version="{version}" Date="{day}">'
        f"<Weaknesses>{weakness_xml}</Weaknesses><Categories>{category_xml}</Categories>"
        f'<Views><View ID="1000" Name="Research Concepts" Type="Graph" Status="Draft"><Objective>x</Objective></View></Views>'
        f"</Weakness_Catalog>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"cwec_v{version}.xml", xml)
    return path
