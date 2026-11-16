"""CTI reference data: vulnerabilities, scores, affected products, KEV entries (class diagram 9.3)."""

from django.db import models


class Severity(models.TextChoices):
    NONE = "NONE", "None"
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class ScoreProvider(models.TextChoices):
    NVD = "NVD", "NVD"
    CNA = "CNA", "CNA"
    CISA_ADP = "CISA_ADP", "CISA ADP"


class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=32, unique=True)
    description = models.TextField()
    published_at = models.DateTimeField(null=True, blank=True)
    # dateUpdated of the CVE record: watermark for incremental loads
    source_updated_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Short name of the CNA that published the record (cveMetadata.assignerShortName), e.g. "fortinet"
    assigner = models.CharField(max_length=64, blank=True)
    # Title given by the CNA (containers.cna.title), when there is one: a feature of model M1
    title = models.CharField(max_length=300, blank=True)
    nvd_status = models.CharField(max_length=32, blank=True)  # NVD connector (Sprint 2)
    epss_score = models.FloatField(null=True, blank=True)  # EPSS connector (Sprint 2)
    epss_percentile = models.FloatField(null=True, blank=True)
    # Effective severity (FR-06), copied after each pipeline run (cti.services.refresh_effective_severity)
    # so that searches can filter on it quickly: the CVSS score of NVD > CNA > CISA ADP, else the severity
    # predicted by the active M1 model (is_severity_predicted = True, effective_score empty).
    # Empty = no CVSS score and no prediction.
    effective_severity = models.CharField(max_length=10, choices=Severity.choices, blank=True, db_index=True)
    effective_score = models.FloatField(null=True, blank=True)
    is_severity_predicted = models.BooleanField(default=False)

    class Meta:
        ordering = ["-published_at"]
        verbose_name_plural = "vulnerabilities"

    def __str__(self) -> str:
        return self.cve_id

    def ordered_metrics(self) -> list["CVSSMetric"]:
        """CVSS scores in the order of FR-06: NVD > CNA > CISA ADP, newest CVSS version first.

        Uses the prefetched cvss_metrics when available.
        """
        order = {ScoreProvider.NVD: 0, ScoreProvider.CNA: 1, ScoreProvider.CISA_ADP: 2}
        return sorted(self.cvss_metrics.all(), key=lambda m: (order.get(m.provider, 9), -float(m.version or 0)))

    def effective_metric(self):
        """CVSS score used as the effective severity (FR-06): the first of ordered_metrics().

        Returns None when no score exists (the severity predicted by M1 is then used, see is_severity_predicted).
        """
        metrics = self.ordered_metrics()
        return metrics[0] if metrics else None

    def ordered_weaknesses(self) -> list[tuple["Weakness", list[str]]]:
        """CWEs of this CVE with the providers that name them, primary CWE first.

        Primary CWE rule (same as the warehouse): NVD > CNA > CISA ADP, weaknesses before categories,
        then the first CWE cited in the record. Uses the prefetched weakness_links when available.
        """
        order = {ScoreProvider.NVD: 0, ScoreProvider.CNA: 1, ScoreProvider.CISA_ADP: 2}
        links = sorted(
            self.weakness_links.all(),
            key=lambda link: (order.get(link.provider, 9), link.weakness.kind == Weakness.Kind.CATEGORY, link.pk),
        )
        grouped: dict[int, tuple[Weakness, list[str]]] = {}
        for link in links:
            grouped.setdefault(link.weakness_id, (link.weakness, []))[1].append(link.get_provider_display())
        return list(grouped.values())


class CVSSMetric(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="cvss_metrics")
    provider = models.CharField(max_length=10, choices=ScoreProvider.choices)
    version = models.CharField(max_length=8)  # "2.0", "3.0", "3.1", "4.0"
    vector = models.CharField(max_length=200, blank=True)
    base_score = models.FloatField()
    severity = models.CharField(max_length=10, choices=Severity.choices)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["vulnerability", "provider", "version"], name="uniq_cvss_per_provider_version"),
            models.CheckConstraint(
                condition=models.Q(base_score__gte=0) & models.Q(base_score__lte=10), name="cvss_score_0_10"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.vulnerability} {self.provider} v{self.version} {self.base_score}"


class Product(models.Model):
    """Normalized product (lowercase vendor and name). Aliases are added with the watchlist (US07)."""

    vendor = models.CharField(max_length=200)
    name = models.CharField(max_length=200)
    cpe_prefix = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["vendor", "name"]
        constraints = [models.UniqueConstraint(fields=["vendor", "name"], name="uniq_product_vendor_name")]

    def __str__(self) -> str:
        return f"{self.vendor} {self.name}"


class AffectedProduct(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="affected_products")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="affected_by")
    versions = models.TextField(blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["vulnerability", "product"], name="uniq_affected_product")]


class KEVEntry(models.Model):
    """CISA Known Exploited Vulnerabilities catalog entry (0..1 per vulnerability)."""

    vulnerability = models.OneToOneField(Vulnerability, on_delete=models.CASCADE, related_name="kev_entry")
    date_added = models.DateField()
    due_date = models.DateField(null=True, blank=True)
    required_action = models.TextField(blank=True)
    ransomware_use = models.BooleanField(default=False)

    class Meta:
        ordering = ["-date_added"]
        verbose_name = "KEV entry"
        verbose_name_plural = "KEV entries"

    def __str__(self) -> str:
        return f"KEV {self.vulnerability}"


class Weakness(models.Model):
    """Entry of the MITRE CWE catalog (weakness or category), e.g. CWE-79.

    A CVE record can name a CWE before the catalog is loaded: the row is then created with an
    empty name, and the cwe connector fills it at its next run.
    """

    class Kind(models.TextChoices):
        WEAKNESS = "WEAKNESS", "Weakness"
        CATEGORY = "CATEGORY", "Category"

    cwe_id = models.CharField(max_length=16, unique=True)  # "CWE-79"
    name = models.CharField(max_length=300, blank=True)
    kind = models.CharField(max_length=10, choices=Kind.choices, blank=True)
    abstraction = models.CharField(max_length=20, blank=True)  # Pillar, Class, Base, Variant, Compound
    status = models.CharField(max_length=20, blank=True)  # Stable, Draft, Incomplete, Deprecated...

    class Meta:
        verbose_name_plural = "weaknesses"

    def __str__(self) -> str:
        return f"{self.cwe_id} {self.name}".strip()

    @property
    def number(self) -> int:
        return int(self.cwe_id.split("-")[1])


class VulnerabilityWeakness(models.Model):
    """Link between a CVE and a CWE, with the organization that published it (CNA, CISA ADP, later NVD)."""

    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="weakness_links")
    weakness = models.ForeignKey(Weakness, on_delete=models.CASCADE, related_name="vulnerability_links")
    provider = models.CharField(max_length=10, choices=ScoreProvider.choices)

    class Meta:
        verbose_name = "vulnerability weakness"
        constraints = [
            models.UniqueConstraint(fields=["vulnerability", "weakness", "provider"], name="uniq_vulnerability_weakness"),
        ]

    def __str__(self) -> str:
        return f"{self.vulnerability} {self.weakness.cwe_id} ({self.provider})"


class Malware(models.Model):
    """Malware family named by ThreatFox, identified by its Malpedia name (e.g. "win.cobalt_strike")."""

    malpedia_id = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=200)  # display name, e.g. "Cobalt Strike"
    category = models.CharField(max_length=50, blank=True)  # target platform, from the Malpedia prefix

    class Meta:
        verbose_name_plural = "malware"

    def __str__(self) -> str:
        return self.name


class Indicator(models.Model):
    """Indicator of compromise (IOC) published by abuse.ch ThreatFox.

    The value is data only: it is never visited, resolved or rendered as a link (risk R9).
    """

    threatfox_id = models.BigIntegerField(unique=True)
    value = models.TextField()
    ioc_type = models.CharField(max_length=50)  # ip:port, domain, url, md5_hash, sha256_hash...
    threat_type = models.CharField(max_length=50)  # botnet_cc, payload_delivery, payload...
    malware = models.ForeignKey(Malware, null=True, blank=True, on_delete=models.SET_NULL, related_name="indicators")
    confidence = models.PositiveSmallIntegerField()  # 0-100
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["first_seen"], name="cti_indicator_first_seen")]

    def __str__(self) -> str:
        return f"{self.ioc_type} {self.value[:60]}"
