from remediation.reports.vex_generator import VEXFinding, VEXGenerator


def test_generate_minimal_vex():
    gen = VEXGenerator(publisher="acme")
    doc = gen.generate(
        document_id="acme-2026-001",
        product_name="checkout",
        product_version="1.4.0",
        findings=[
            VEXFinding(
                cve="CVE-2021-44228",
                status="not_affected",
                justification="vulnerable_code_not_present",
                impact_statement="Reachability engine confirmed Log4j classes are absent.",
            )
        ],
    )
    assert doc["document"]["category"] == "csaf_vex"
    assert doc["document"]["csaf_version"] == "2.0"
    vuln = doc["vulnerabilities"][0]
    assert vuln["cve"] == "CVE-2021-44228"
    assert vuln["product_status"]["known_not_affected"] == ["checkout@1.4.0"]
    assert vuln["flags"][0]["label"] == "vulnerable_code_not_present"


def test_not_affected_requires_justification():
    gen = VEXGenerator(publisher="acme")
    try:
        gen.generate(
            document_id="x",
            product_name="p",
            product_version="1",
            findings=[VEXFinding(cve="CVE-1", status="not_affected")],
        )
    except ValueError as e:
        assert "justification" in str(e)
    else:
        raise AssertionError("expected ValueError")
