from django.test import TestCase

from dojo.models import Test
from dojo.tools.checkmarx_sca.parser import CheckmarxSCAParser


class TestCheckmarxSCAParser(TestCase):
    def test_checkmarx_sca_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/checkmarx_sca/checkmarx_sca_zero_vul.json")
        parser = CheckmarxSCAParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_checkmarx_sca_parser_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/checkmarx_sca/checkmarx_sca_one_vul.json")
        parser = CheckmarxSCAParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("cryptography", findings[0].component_name)
        self.assertEqual("44.0.0", findings[0].component_version)

    def test_checkmarx_sca_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/checkmarx_sca/checkmarx_sca_many_vul.json")
        parser = CheckmarxSCAParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(10, len(findings))
