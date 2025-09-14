#!/usr/bin/env python3
"""
Test Suite for Enhanced Intelligent Reporting System
Tests the new deep thinking and intelligent processing capabilities
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
import sys
import logging

# Add the main directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

class TestEnhancedReporting(unittest.TestCase):
    """Test enhanced reporting functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.report_dir = self.test_dir / "report"
        self.report_dir.mkdir(exist_ok=True)
        
        # Sample vulnerability data for testing
        self.sample_vulns = [
            {
                "info": {
                    "name": "SQL Injection",
                    "severity": "critical",
                    "description": "SQL injection vulnerability found"
                },
                "template-id": "sqli-basic",
                "matched-at": "https://test.example.com/login",
                "response": "SQL error detected"
            },
            {
                "info": {
                    "name": "XSS Vulnerability",
                    "severity": "high",
                    "description": "Cross-site scripting vulnerability"
                },
                "template-id": "xss-reflected",
                "matched-at": "https://test.example.com/search",
                "response": "XSS payload executed"
            },
            {
                "info": {
                    "name": "SSL Misconfiguration",
                    "severity": "medium",
                    "description": "SSL/TLS configuration issue"
                },
                "template-id": "ssl-weak-cipher",
                "matched-at": "https://test.example.com",
                "response": "Weak cipher suite detected"
            }
        ]
        
        # Sample configuration
        self.test_config = {
            "enhanced_reporting": {
                "enabled": True,
                "enable_deep_analysis": True,
                "enable_correlation": True,
                "enable_threat_intelligence": True,
                "enable_narrative_generation": True
            },
            "business_context": {
                "asset_criticality": 8.0,
                "data_sensitivity": 9.0,
                "availability_requirement": 8.5,
                "compliance_requirements": ["GDPR", "SOX"],
                "business_hours_impact": 2.0,
                "revenue_impact_per_hour": 50000.0
            }
        }
        
        # Sample recon and vuln results
        self.sample_recon = {
            "test.example.com": {
                "subdomains": ["www.test.example.com", "api.test.example.com"],
                "open_ports": [{"host": "test.example.com", "port": 443, "proto": "tcp"}],
                "http_info": [{"url": "https://test.example.com", "status_code": 200}]
            }
        }
        
        self.sample_vuln_results = {
            "test.example.com": {
                "nuclei_raw": [json.dumps(vuln) for vuln in self.sample_vulns],
                "nuclei_parsed": {
                    "critical": [self.sample_vulns[0]],
                    "high": [self.sample_vulns[1]],
                    "medium": [self.sample_vulns[2]],
                    "low": [],
                    "info": []
                },
                "risk_score": 25
            }
        }
    
    def tearDown(self):
        """Clean up test environment"""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_intelligent_report_analyzer_import(self):
        """Test that intelligent report analyzer can be imported"""
        try:
            from intelligent_report_engine import IntelligentReportAnalyzer
            analyzer = IntelligentReportAnalyzer(self.test_config)
            self.assertIsNotNone(analyzer)
            self.assertIsNotNone(analyzer.config)
            self.assertIsNotNone(analyzer.logger)
        except ImportError as e:
            self.fail(f"Failed to import IntelligentReportAnalyzer: {e}")
    
    def test_vulnerability_context_creation(self):
        """Test vulnerability context creation"""
        try:
            from intelligent_report_engine import IntelligentReportAnalyzer
            analyzer = IntelligentReportAnalyzer(self.test_config)
            
            # Analyze sample vulnerabilities
            enhanced_vulns = analyzer.analyze_vulnerability_intelligence(self.sample_vulns)
            
            self.assertGreater(len(enhanced_vulns), 0)
            
            # Check that enhanced vulnerabilities have required attributes
            for vuln in enhanced_vulns:
                self.assertTrue(hasattr(vuln, 'cvss_score'))
                self.assertTrue(hasattr(vuln, 'exploitability'))
                self.assertTrue(hasattr(vuln, 'confidence'))
                self.assertTrue(hasattr(vuln, 'business_impact'))
                self.assertTrue(hasattr(vuln, 'attack_vector'))
                
                # Validate score ranges
                self.assertGreaterEqual(vuln.cvss_score, 0.0)
                self.assertLessEqual(vuln.cvss_score, 10.0)
                self.assertGreaterEqual(vuln.exploitability, 0.0)
                self.assertLessEqual(vuln.exploitability, 1.0)
                self.assertGreaterEqual(vuln.confidence, 0.0)
                self.assertLessEqual(vuln.confidence, 1.0)
                
        except Exception as e:
            self.fail(f"Vulnerability context creation failed: {e}")
    
    def test_advanced_risk_calculator(self):
        """Test advanced risk calculation"""
        try:
            from intelligent_report_engine import AdvancedRiskCalculator, IntelligentReportAnalyzer
            
            analyzer = IntelligentReportAnalyzer(self.test_config)
            enhanced_vulns = analyzer.analyze_vulnerability_intelligence(self.sample_vulns)
            
            risk_calculator = AdvancedRiskCalculator()
            risk_assessment = risk_calculator.calculate_contextual_risk(enhanced_vulns)
            
            # Validate risk assessment structure
            self.assertIn("overall_risk_score", risk_assessment)
            self.assertIn("risk_level", risk_assessment)
            self.assertIn("business_impact_score", risk_assessment)
            self.assertIn("severity_breakdown", risk_assessment)
            self.assertIn("recommendations", risk_assessment)
            
            # Validate risk level is appropriate
            self.assertIn(risk_assessment["risk_level"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"])
            
            # Validate recommendations are provided
            self.assertIsInstance(risk_assessment["recommendations"], list)
            self.assertGreater(len(risk_assessment["recommendations"]), 0)
            
        except Exception as e:
            self.fail(f"Advanced risk calculation failed: {e}")
    
    def test_vulnerability_correlation_engine(self):
        """Test vulnerability correlation analysis"""
        try:
            from intelligent_report_engine import VulnerabilityCorrelationEngine, IntelligentReportAnalyzer
            
            analyzer = IntelligentReportAnalyzer(self.test_config)
            enhanced_vulns = analyzer.analyze_vulnerability_intelligence(self.sample_vulns)
            
            correlation_engine = VulnerabilityCorrelationEngine()
            correlations = correlation_engine.analyze_correlations(enhanced_vulns)
            
            # Validate correlation structure
            self.assertIn("attack_chains", correlations)
            self.assertIn("vulnerability_clusters", correlations)
            self.assertIn("amplification_scenarios", correlations)
            self.assertIn("dependency_graph", correlations)
            self.assertIn("risk_amplification_factor", correlations)
            
            # Validate data types
            self.assertIsInstance(correlations["attack_chains"], list)
            self.assertIsInstance(correlations["vulnerability_clusters"], list)
            self.assertIsInstance(correlations["amplification_scenarios"], list)
            self.assertIsInstance(correlations["dependency_graph"], dict)
            self.assertIsInstance(correlations["risk_amplification_factor"], (int, float))
            
        except Exception as e:
            self.fail(f"Vulnerability correlation analysis failed: {e}")
    
    def test_threat_intelligence_aggregator(self):
        """Test threat intelligence aggregation"""
        try:
            from intelligent_report_engine import ThreatIntelligenceAggregator, IntelligentReportAnalyzer
            
            analyzer = IntelligentReportAnalyzer(self.test_config)
            enhanced_vulns = analyzer.analyze_vulnerability_intelligence(self.sample_vulns)
            
            threat_aggregator = ThreatIntelligenceAggregator(self.test_config)
            threat_intel = threat_aggregator.aggregate_threat_intelligence(
                enhanced_vulns, ["test.example.com"]
            )
            
            # Validate threat intelligence structure
            self.assertTrue(hasattr(threat_intel, 'reputation_score'))
            self.assertTrue(hasattr(threat_intel, 'known_malicious_ips'))
            self.assertTrue(hasattr(threat_intel, 'suspicious_domains'))
            self.assertTrue(hasattr(threat_intel, 'threat_feeds'))
            
            # Validate reputation score range
            self.assertGreaterEqual(threat_intel.reputation_score, 0.0)
            self.assertLessEqual(threat_intel.reputation_score, 100.0)
            
        except Exception as e:
            self.fail(f"Threat intelligence aggregation failed: {e}")
    
    def test_enhanced_report_controller(self):
        """Test enhanced report controller integration"""
        try:
            from enhanced_report_controller import EnhancedReportController
            
            # Create logger for testing
            logger = logging.getLogger("test_logger")
            
            controller = EnhancedReportController(self.test_config, logger)
            
            # Test report generation
            enhanced_report = controller.generate_enhanced_report(
                self.test_dir,
                self.sample_recon,
                self.sample_vuln_results,
                ["test.example.com"]
            )
            
            # Validate enhanced report structure
            self.assertIn("report_metadata", enhanced_report)
            self.assertIn("executive_summary", enhanced_report)
            self.assertIn("risk_assessment", enhanced_report)
            self.assertIn("vulnerability_analysis", enhanced_report)
            self.assertIn("recommendations", enhanced_report)
            
            # Validate metadata
            metadata = enhanced_report["report_metadata"]
            self.assertIn("analysis_engine_version", metadata)
            self.assertIn("total_vulnerabilities", metadata)
            self.assertIn("analysis_depth", metadata)
            
            # Validate executive summary has business context
            exec_summary = enhanced_report["executive_summary"]
            self.assertIn("security_posture", exec_summary)
            self.assertIn("business_impact", exec_summary)
            self.assertIn("key_insights", exec_summary)
            
        except Exception as e:
            self.fail(f"Enhanced report controller test failed: {e}")
    
    def test_enhanced_html_report_generation(self):
        """Test enhanced HTML report generation"""
        try:
            # Test the HTML report generation function
            from bl4ckc3ll_p4nth30n import generate_enhanced_intelligent_html_report
            
            # Create sample enhanced report data
            enhanced_report_data = {
                "report_metadata": {
                    "run_id": "test_run",
                    "analysis_engine_version": "9.0.0-test",
                    "generation_timestamp": "2024-01-01T12:00:00",
                    "analysis_depth": "DEEP"
                },
                "executive_summary": {
                    "scan_overview": {
                        "targets_scanned": 1,
                        "subdomains_discovered": 2,
                        "scan_completion_time": "2024-01-01 12:00:00"
                    },
                    "security_posture": {
                        "overall_risk_level": "HIGH",
                        "vulnerabilities_found": 3,
                        "critical_findings_count": 1
                    },
                    "business_impact": {
                        "impact_score": 75.0,
                        "time_to_compromise": "Hours",
                        "estimated_financial_impact": {
                            "total_potential_impact": 100000
                        }
                    },
                    "key_insights": [
                        {
                            "priority": "HIGH",
                            "title": "Critical SQL Injection Found",
                            "description": "Database access vulnerability detected",
                            "business_implication": "Potential data breach"
                        }
                    ]
                },
                "risk_assessment": {
                    "overall_risk_score": 75.0,
                    "risk_level": "HIGH",
                    "attack_vector_distribution": {
                        "web_application": {"count": 2, "percentage": 66.7},
                        "network": {"count": 1, "percentage": 33.3}
                    }
                },
                "threat_intelligence": {
                    "reputation_score": 85.0
                },
                "vulnerability_analysis": {
                    "correlation_analysis": {
                        "attack_chains": [
                            {
                                "name": "SQL Injection Chain",
                                "target": "test.example.com",
                                "risk_multiplier": 2.0
                            }
                        ]
                    },
                    "attack_surface_analysis": {
                        "surface_metrics": {
                            "total_targets": 1,
                            "total_services": 1,
                            "vulnerability_density": 3.0
                        }
                    }
                },
                "executive_narrative": {
                    "executive_storyline": [
                        {
                            "section": "Situation Assessment",
                            "content": "Critical security vulnerabilities detected requiring immediate attention."
                        }
                    ],
                    "board_summary": {
                        "headline": "High-risk security vulnerabilities identified",
                        "timeline": "Immediate action required"
                    }
                },
                "remediation_roadmap": {
                    "immediate_actions": {
                        "timeline": "0-24 hours",
                        "success_criteria": "Critical vulnerabilities patched",
                        "actions": [
                            {
                                "vulnerability": "sqli-basic",
                                "target": "test.example.com",
                                "effort": "Medium",
                                "justification": "Prevents data breach"
                            }
                        ]
                    }
                },
                "recommendations": {
                    "immediate_actions": [
                        "Patch SQL injection vulnerability immediately",
                        "Review authentication mechanisms"
                    ],
                    "strategic_initiatives": [
                        "Implement Web Application Firewall",
                        "Enhance security monitoring"
                    ],
                    "monitoring_improvements": [
                        "Deploy SIEM solution",
                        "Implement continuous vulnerability scanning"
                    ]
                },
                "appendices": {
                    "analysis_confidence": {
                        "overall_confidence": "HIGH"
                    },
                    "methodology": {
                        "analysis_framework": "Bl4ckC3ll_PANTHEON Enhanced Intelligence Engine"
                    }
                }
            }
            
            # Generate HTML report
            generate_enhanced_intelligent_html_report(enhanced_report_data, self.report_dir)
            
            # Check that HTML file was created
            html_file = self.report_dir / "intelligent_report.html"
            self.assertTrue(html_file.exists())
            
            # Check HTML content contains expected elements
            html_content = html_file.read_text()
            self.assertIn("Intelligent Security Assessment Report", html_content)
            self.assertIn("Executive Summary", html_content)
            self.assertIn("Threat Intelligence", html_content)
            self.assertIn("Vulnerability Analysis", html_content)
            self.assertIn("Remediation Roadmap", html_content)
            self.assertIn("test_run", html_content)
            
        except Exception as e:
            self.fail(f"Enhanced HTML report generation failed: {e}")
    
    def test_integration_with_main_orchestrator(self):
        """Test integration with main orchestrator"""
        try:
            # Test that enhanced reporting can be imported and configured
            import bl4ckc3ll_p4nth30n as main
            
            # Check default configuration includes enhanced reporting
            cfg = main.DEFAULT_CFG
            self.assertIn("enhanced_reporting", cfg)
            self.assertTrue(cfg["enhanced_reporting"]["enabled"])
            self.assertIn("business_context", cfg["enhanced_reporting"])
            
            # Test configuration validation
            enhanced_config = cfg["enhanced_reporting"]
            self.assertIn("enable_deep_analysis", enhanced_config)
            self.assertIn("enable_correlation", enhanced_config)
            self.assertIn("enable_threat_intelligence", enhanced_config)
            self.assertIn("enable_narrative_generation", enhanced_config)
            
            business_context = enhanced_config["business_context"]
            self.assertIn("asset_criticality", business_context)
            self.assertIn("compliance_requirements", business_context)
            self.assertIn("revenue_impact_per_hour", business_context)
            
        except Exception as e:
            self.fail(f"Integration test failed: {e}")
    
    def test_performance_and_error_handling(self):
        """Test performance and error handling"""
        try:
            from intelligent_report_engine import IntelligentReportAnalyzer
            
            # Test with empty data
            analyzer = IntelligentReportAnalyzer(self.test_config)
            empty_result = analyzer.analyze_vulnerability_intelligence([])
            self.assertEqual(len(empty_result), 0)
            
            # Test with malformed vulnerability data
            malformed_vulns = [
                {"invalid": "data"},
                {"info": {}, "template-id": "test"},
                None,
                ""
            ]
            
            # Should handle gracefully without crashing
            result = analyzer.analyze_vulnerability_intelligence(malformed_vulns)
            self.assertIsInstance(result, list)
            
        except Exception as e:
            self.fail(f"Performance and error handling test failed: {e}")


class TestReportingFeatures(unittest.TestCase):
    """Test specific reporting features"""
    
    def test_executive_narrative_generation(self):
        """Test executive narrative generation"""
        try:
            from enhanced_report_controller import EnhancedReportController
            import logging
            
            config = {
                "enhanced_reporting": {
                    "enable_narrative_generation": True
                }
            }
            
            logger = logging.getLogger("test")
            controller = EnhancedReportController(config, logger)
            
            # Test narrative generation components exist
            self.assertTrue(hasattr(controller, 'narrative_generation'))
            self.assertTrue(controller.narrative_generation)
            
        except Exception as e:
            self.fail(f"Executive narrative test failed: {e}")
    
    def test_business_impact_calculation(self):
        """Test business impact calculation"""
        try:
            from intelligent_report_engine import AdvancedRiskCalculator, BusinessContext
            
            # Create business context with specific values
            business_context = BusinessContext(
                asset_criticality=9.0,
                data_sensitivity=8.0,
                availability_requirement=7.0,
                compliance_requirements=["GDPR", "HIPAA"],
                business_hours_impact=2.0,
                revenue_impact_per_hour=100000.0
            )
            
            calculator = AdvancedRiskCalculator(business_context)
            
            # Validate business context is applied
            self.assertEqual(calculator.business_context.asset_criticality, 9.0)
            self.assertEqual(calculator.business_context.revenue_impact_per_hour, 100000.0)
            
        except Exception as e:
            self.fail(f"Business impact calculation test failed: {e}")


def run_enhanced_reporting_tests():
    """Run all enhanced reporting tests"""
    print("\n🧪 Starting Enhanced Reporting Test Suite")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedReporting))
    suite.addTests(loader.loadTestsFromTestCase(TestReportingFeatures))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 ENHANCED REPORTING TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Successful: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\n🚨 ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Error:')[-1].strip()}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100) if result.testsRun > 0 else 0
    print(f"\nSuccess Rate: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("🎉 Enhanced reporting system is working excellently!")
    elif success_rate >= 75:
        print("✅ Enhanced reporting system is working well with minor issues.")
    elif success_rate >= 50:
        print("⚠️  Enhanced reporting system has some issues that need attention.")
    else:
        print("❌ Enhanced reporting system has significant issues that need immediate attention.")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_enhanced_reporting_tests()
    exit(0 if success else 1)