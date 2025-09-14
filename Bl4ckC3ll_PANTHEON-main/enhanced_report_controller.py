#!/usr/bin/env python3
"""
Enhanced Report Controller for Bl4ckC3ll_PANTHEON
Integrates intelligent analysis with existing report generation

Author: @cxb3rf1lth
"""

import json
import logging
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import asdict

from intelligent_report_engine import (
    IntelligentReportAnalyzer, AdvancedRiskCalculator, VulnerabilityCorrelationEngine,
    ThreatIntelligenceAggregator, VulnerabilityContext, BusinessContext, ThreatLevel
)


class EnhancedReportController:
    """Enhanced report controller with intelligent analysis capabilities"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Initialize intelligent analysis components
        self.report_analyzer = IntelligentReportAnalyzer(config)
        self.risk_calculator = AdvancedRiskCalculator(self._create_business_context())
        self.correlation_engine = VulnerabilityCorrelationEngine()
        self.threat_aggregator = ThreatIntelligenceAggregator(config)
        
        # Enhanced reporting configuration
        self.reporting_config = config.get("enhanced_reporting", {})
        self.enable_deep_analysis = self.reporting_config.get("enable_deep_analysis", True)
        self.enable_correlation = self.reporting_config.get("enable_correlation", True)
        self.enable_threat_intel = self.reporting_config.get("enable_threat_intelligence", True)
        self.narrative_generation = self.reporting_config.get("enable_narrative_generation", True)
        
    def _create_business_context(self) -> BusinessContext:
        """Create business context from configuration"""
        business_config = self.config.get("business_context", {})
        
        return BusinessContext(
            asset_criticality=business_config.get("asset_criticality", 5.0),
            data_sensitivity=business_config.get("data_sensitivity", 5.0),
            availability_requirement=business_config.get("availability_requirement", 5.0),
            compliance_requirements=business_config.get("compliance_requirements", ["GDPR"]),
            business_hours_impact=business_config.get("business_hours_impact", 1.0),
            revenue_impact_per_hour=business_config.get("revenue_impact_per_hour", 10000.0)
        )
    
    def generate_enhanced_report(self, run_dir: Path, recon_results: Dict[str, Any], 
                               vuln_results: Dict[str, Any], targets: List[str]) -> Dict[str, Any]:
        """Generate enhanced report with intelligent analysis"""
        self.logger.info("Starting enhanced report generation with intelligent analysis")
        
        try:
            # Extract vulnerabilities for analysis
            vulnerabilities = self._extract_vulnerabilities(vuln_results)
            
            # Apply intelligent analysis
            if self.enable_deep_analysis and vulnerabilities:
                self.logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities with intelligent engine")
                enhanced_vulnerabilities = self.report_analyzer.analyze_vulnerability_intelligence(vulnerabilities)
            else:
                enhanced_vulnerabilities = vulnerabilities
            
            # Calculate advanced risk assessment
            if enhanced_vulnerabilities:
                self.logger.info("Calculating contextual risk assessment")
                risk_assessment = self.risk_calculator.calculate_contextual_risk(enhanced_vulnerabilities)
            else:
                risk_assessment = self.risk_calculator.calculate_contextual_risk([])
            
            # Perform correlation analysis
            correlations = {}
            if self.enable_correlation and enhanced_vulnerabilities:
                self.logger.info("Performing vulnerability correlation analysis")
                correlations = self.correlation_engine.analyze_correlations(enhanced_vulnerabilities)
            
            # Aggregate threat intelligence
            threat_intelligence = {}
            if self.enable_threat_intel:
                self.logger.info("Aggregating threat intelligence")
                threat_intel = self.threat_aggregator.aggregate_threat_intelligence(
                    enhanced_vulnerabilities, targets
                )
                threat_intelligence = asdict(threat_intel)
            
            # Generate executive narrative
            executive_narrative = self._generate_executive_narrative(
                enhanced_vulnerabilities, risk_assessment, correlations, threat_intelligence
            )
            
            # Generate technical analysis
            technical_analysis = self._generate_technical_analysis(
                enhanced_vulnerabilities, correlations
            )
            
            # Create comprehensive report structure
            enhanced_report = {
                "report_metadata": {
                    "run_id": run_dir.name,
                    "generation_timestamp": datetime.now().isoformat(),
                    "analysis_engine_version": "9.0.0-enhanced",
                    "targets_analyzed": targets,
                    "total_vulnerabilities": len(enhanced_vulnerabilities),
                    "analysis_depth": "DEEP" if self.enable_deep_analysis else "STANDARD"
                },
                
                "executive_summary": self._generate_enhanced_executive_summary(
                    recon_results, enhanced_vulnerabilities, risk_assessment
                ),
                
                "risk_assessment": risk_assessment,
                
                "threat_intelligence": threat_intelligence,
                
                "vulnerability_analysis": {
                    "enhanced_vulnerabilities": [self._serialize_vulnerability_context(v) for v in enhanced_vulnerabilities],
                    "correlation_analysis": correlations,
                    "attack_surface_analysis": self._analyze_attack_surface(recon_results, enhanced_vulnerabilities),
                    "temporal_analysis": self._perform_temporal_analysis(enhanced_vulnerabilities)
                },
                
                "executive_narrative": executive_narrative,
                
                "technical_analysis": technical_analysis,
                
                "remediation_roadmap": self._generate_remediation_roadmap(
                    enhanced_vulnerabilities, risk_assessment
                ),
                
                "compliance_assessment": self._generate_compliance_assessment(
                    enhanced_vulnerabilities, risk_assessment
                ),
                
                "recommendations": {
                    "immediate_actions": risk_assessment.get("recommendations", [])[:5],
                    "strategic_initiatives": self._generate_strategic_recommendations(risk_assessment),
                    "monitoring_improvements": self._generate_monitoring_recommendations(enhanced_vulnerabilities)
                },
                
                "appendices": {
                    "raw_recon_data": recon_results,
                    "raw_vulnerability_data": vuln_results,
                    "analysis_confidence": self._calculate_analysis_confidence(enhanced_vulnerabilities),
                    "methodology": self._document_methodology()
                }
            }
            
            self.logger.info("Enhanced report generation completed successfully")
            return enhanced_report
            
        except Exception as e:
            self.logger.error(f"Enhanced report generation failed: {e}")
            # Fallback to basic report structure
            return self._generate_fallback_report(run_dir, recon_results, vuln_results, targets)
    
    def _serialize_vulnerability_context(self, vuln: VulnerabilityContext) -> Dict[str, Any]:
        """Serialize VulnerabilityContext to JSON-serializable dict"""
        vuln_dict = asdict(vuln)
        # Convert enum to string
        if 'attack_vector' in vuln_dict:
            vuln_dict['attack_vector'] = vuln_dict['attack_vector'].value if hasattr(vuln_dict['attack_vector'], 'value') else str(vuln_dict['attack_vector'])
        return vuln_dict
    
    def _extract_vulnerabilities(self, vuln_results: Dict[str, Any]) -> List[VulnerabilityContext]:
        """Extract and convert vulnerabilities to enhanced context objects"""
        vulnerabilities = []
        
        for target, data in vuln_results.items():
            nuclei_raw = data.get("nuclei_raw", [])
            
            for line in nuclei_raw:
                try:
                    if isinstance(line, str) and line.strip():
                        vuln_data = json.loads(line)
                        # Create basic vulnerability context that will be enhanced by the analyzer
                        vuln_dict = {
                            "info": vuln_data.get("info", {}),
                            "template-id": vuln_data.get("template-id", "unknown"),
                            "matched-at": vuln_data.get("matched-at", target),
                            "response": vuln_data.get("response", "")
                        }
                        vulnerabilities.append(vuln_dict)
                except (json.JSONDecodeError, KeyError) as e:
                    self.logger.warning(f"Failed to parse vulnerability data: {e}")
                    continue
        
        return vulnerabilities
    
    def _generate_enhanced_executive_summary(self, recon_results: Dict[str, Any], 
                                           vulnerabilities: List[VulnerabilityContext], 
                                           risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate enhanced executive summary with business context"""
        # Calculate enhanced metrics
        total_targets = len(recon_results)
        total_subdomains = sum(len(data.get("subdomains", [])) for data in recon_results.values())
        total_open_ports = sum(len(data.get("open_ports", [])) for data in recon_results.values())
        total_http_services = sum(len(data.get("http_info", [])) for data in recon_results.values())
        
        # Vulnerability statistics
        severity_counts = risk_assessment.get("severity_breakdown", {})
        total_vulnerabilities = sum(severity_counts.values())
        
        # Business impact analysis
        business_impact_score = risk_assessment.get("business_impact_score", 0)
        estimated_financial_impact = self._estimate_financial_impact(vulnerabilities, risk_assessment)
        
        # Key insights
        key_insights = self._generate_key_insights(vulnerabilities, risk_assessment)
        
        return {
            "scan_overview": {
                "targets_scanned": total_targets,
                "subdomains_discovered": total_subdomains,
                "open_ports_found": total_open_ports,
                "http_services_identified": total_http_services,
                "scan_completion_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_duration": "Estimated based on analysis depth"
            },
            
            "security_posture": {
                "overall_risk_level": risk_assessment.get("risk_level", "UNKNOWN"),
                "risk_score": risk_assessment.get("overall_risk_score", 0),
                "vulnerabilities_found": total_vulnerabilities,
                "severity_distribution": severity_counts,
                "critical_findings_count": severity_counts.get("critical", 0),
                "exploitable_vulnerabilities": len([v for v in vulnerabilities if hasattr(v, 'exploitability') and v.exploitability > 0.7])
            },
            
            "business_impact": {
                "impact_score": business_impact_score,
                "estimated_financial_impact": estimated_financial_impact,
                "time_to_compromise": risk_assessment.get("time_to_compromise", "Unknown"),
                "affected_business_functions": self._identify_affected_business_functions(vulnerabilities),
                "compliance_violations": len(risk_assessment.get("compliance_impact", []))
            },
            
            "key_insights": key_insights,
            
            "immediate_priorities": {
                "critical_actions": risk_assessment.get("recommendations", [])[:3],
                "quick_wins": self._identify_quick_wins(vulnerabilities),
                "resource_requirements": self._estimate_resource_requirements(vulnerabilities)
            }
        }
    
    def _estimate_financial_impact(self, vulnerabilities: List[VulnerabilityContext], 
                                 risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate potential financial impact"""
        business_context = self._create_business_context()
        
        # Calculate potential downtime impact
        high_impact_vulns = [v for v in vulnerabilities if hasattr(v, 'business_impact') and v.business_impact >= 7.0]
        critical_vulns = [v for v in vulnerabilities if hasattr(v, 'severity') and v.severity.lower() == 'critical']
        
        # Estimate downtime scenarios
        if critical_vulns:
            potential_downtime_hours = 24  # Assume 24 hours for critical vulnerabilities
        elif high_impact_vulns:
            potential_downtime_hours = 8   # Assume 8 hours for high-impact vulnerabilities
        else:
            potential_downtime_hours = 2   # Assume 2 hours for other scenarios
        
        revenue_impact = potential_downtime_hours * business_context.revenue_impact_per_hour
        
        # Add remediation costs
        remediation_cost = len(vulnerabilities) * 500  # Assume $500 per vulnerability for remediation
        
        # Add compliance penalty estimates
        compliance_penalties = 0
        if risk_assessment.get("compliance_impact"):
            compliance_penalties = 50000  # Base compliance penalty estimate
        
        return {
            "potential_revenue_loss": revenue_impact,
            "estimated_remediation_cost": remediation_cost,
            "potential_compliance_penalties": compliance_penalties,
            "total_potential_impact": revenue_impact + remediation_cost + compliance_penalties,
            "risk_basis": f"Based on {potential_downtime_hours}h downtime scenario"
        }
    
    def _generate_key_insights(self, vulnerabilities: List[VulnerabilityContext], 
                             risk_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate key business insights from the analysis"""
        insights = []
        
        # Risk level insight
        risk_level = risk_assessment.get("risk_level", "UNKNOWN")
        if risk_level in ["CRITICAL", "HIGH"]:
            insights.append({
                "type": "RISK_ALERT",
                "priority": "HIGH",
                "title": f"{risk_level} Risk Level Detected",
                "description": f"Organization faces {risk_level.lower()} cybersecurity risk requiring immediate attention",
                "business_implication": "Potential for significant business disruption and financial loss"
            })
        
        # Attack surface insight
        if len(set(v.target for v in vulnerabilities if hasattr(v, 'target'))) > 10:
            insights.append({
                "type": "ATTACK_SURFACE",
                "priority": "MEDIUM",
                "title": "Large Attack Surface Detected",
                "description": "Multiple systems and services exposed to potential attacks",
                "business_implication": "Increased complexity in security management and higher attack probability"
            })
        
        # Exploitability insight
        highly_exploitable = [v for v in vulnerabilities if hasattr(v, 'exploitability') and v.exploitability > 0.8]
        if highly_exploitable:
            insights.append({
                "type": "EXPLOITABILITY",
                "priority": "HIGH",
                "title": f"{len(highly_exploitable)} Highly Exploitable Vulnerabilities",
                "description": "Vulnerabilities with readily available exploit tools and techniques",
                "business_implication": "High probability of successful attacks with minimal attacker effort"
            })
        
        # Compliance insight
        if risk_assessment.get("compliance_impact"):
            insights.append({
                "type": "COMPLIANCE",
                "priority": "HIGH",
                "title": "Compliance Violations Detected",
                "description": "Security findings may violate regulatory requirements",
                "business_implication": "Potential for regulatory penalties and reputation damage"
            })
        
        return insights
    
    def _identify_affected_business_functions(self, vulnerabilities: List[VulnerabilityContext]) -> List[str]:
        """Identify affected business functions based on vulnerabilities"""
        functions = set()
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if any(pattern in template_lower for pattern in ["auth", "login", "session"]):
                functions.add("Authentication & Access Control")
            
            if any(pattern in template_lower for pattern in ["payment", "cart", "checkout"]):
                functions.add("E-commerce & Payments")
            
            if any(pattern in template_lower for pattern in ["data", "database", "sql"]):
                functions.add("Data Management")
            
            if any(pattern in template_lower for pattern in ["admin", "management", "config"]):
                functions.add("System Administration")
            
            if any(pattern in template_lower for pattern in ["api", "service", "endpoint"]):
                functions.add("API & Integration Services")
            
            if any(pattern in template_lower for pattern in ["mail", "smtp", "email"]):
                functions.add("Email & Communication")
        
        return list(functions) if functions else ["General Business Operations"]
    
    def _identify_quick_wins(self, vulnerabilities: List[VulnerabilityContext]) -> List[Dict[str, Any]]:
        """Identify quick win remediation opportunities"""
        quick_wins = []
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'remediation_complexity') or not hasattr(vuln, 'business_impact'):
                continue
                
            # Low complexity, medium+ impact = quick win
            if vuln.remediation_complexity <= 2 and vuln.business_impact >= 5.0:
                quick_wins.append({
                    "vulnerability": vuln.template_id,
                    "target": getattr(vuln, 'target', 'Unknown'),
                    "effort": "Low",
                    "impact": "Medium-High",
                    "estimated_time": "1-4 hours"
                })
        
        return sorted(quick_wins, key=lambda x: x.get("impact", ""), reverse=True)[:5]
    
    def _estimate_resource_requirements(self, vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Estimate resource requirements for remediation"""
        if not vulnerabilities:
            return {"total_effort": "Minimal", "timeline": "Ongoing monitoring"}
        
        total_complexity = sum(getattr(v, 'remediation_complexity', 3) for v in vulnerabilities)
        avg_complexity = total_complexity / len(vulnerabilities)
        
        # Estimate based on complexity and count
        if avg_complexity <= 2:
            effort_level = "Low"
            timeline = "1-2 weeks"
            team_size = "1-2 engineers"
        elif avg_complexity <= 3:
            effort_level = "Medium"
            timeline = "2-4 weeks"
            team_size = "2-3 engineers"
        else:
            effort_level = "High"
            timeline = "4-8 weeks"
            team_size = "3-5 engineers + specialists"
        
        return {
            "total_effort": effort_level,
            "estimated_timeline": timeline,
            "recommended_team_size": team_size,
            "specialist_skills_needed": self._identify_specialist_skills(vulnerabilities)
        }
    
    def _identify_specialist_skills(self, vulnerabilities: List[VulnerabilityContext]) -> List[str]:
        """Identify specialist skills needed for remediation"""
        skills = set()
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'attack_vector'):
                continue
                
            if vuln.attack_vector.value == "web_application":
                skills.add("Web Application Security")
            elif vuln.attack_vector.value == "network":
                skills.add("Network Security")
            elif vuln.attack_vector.value == "configuration":
                skills.add("System Configuration")
            elif vuln.attack_vector.value == "system":
                skills.add("System Administration")
        
        return list(skills) if skills else ["General Security"]
    
    def _generate_executive_narrative(self, vulnerabilities: List[VulnerabilityContext], 
                                    risk_assessment: Dict[str, Any], correlations: Dict[str, Any],
                                    threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive narrative with business context"""
        if not self.narrative_generation:
            return {"narrative_disabled": "Executive narrative generation disabled in configuration"}
        
        # Create storyline based on findings
        storyline = []
        
        # Opening assessment
        risk_level = risk_assessment.get("risk_level", "UNKNOWN")
        total_vulns = len(vulnerabilities)
        
        if risk_level in ["CRITICAL", "HIGH"]:
            storyline.append({
                "section": "Situation Assessment",
                "content": f"The security assessment has identified a {risk_level.lower()} risk situation with {total_vulns} vulnerabilities across the analyzed infrastructure. Immediate executive attention and resource allocation are required to address these security gaps before they can be exploited by malicious actors."
            })
        else:
            storyline.append({
                "section": "Situation Assessment", 
                "content": f"The security assessment reveals a {risk_level.lower()} risk profile with {total_vulns} identified vulnerabilities. While the overall risk is manageable, proactive remediation will strengthen the organization's security posture and reduce potential attack vectors."
            })
        
        # Attack landscape analysis
        if correlations.get("attack_chains"):
            attack_chains = len(correlations["attack_chains"])
            storyline.append({
                "section": "Attack Landscape",
                "content": f"Analysis has identified {attack_chains} potential attack chains where vulnerabilities could be chained together for maximum impact. These represent the most critical risk paths that attackers might exploit to achieve their objectives, potentially bypassing multiple security controls in sequence."
            })
        
        # Business impact narrative
        business_impact = risk_assessment.get("business_impact_score", 0)
        if business_impact > 60:
            storyline.append({
                "section": "Business Impact",
                "content": f"The identified vulnerabilities pose significant business risk with a calculated impact score of {business_impact:.1f}/100. Key business functions including {', '.join(self._identify_affected_business_functions(vulnerabilities)[:3])} could be disrupted, potentially affecting revenue, customer trust, and regulatory compliance."
            })
        
        # Threat intelligence narrative
        if threat_intelligence.get("reputation_score", 100) < 80:
            storyline.append({
                "section": "Threat Intelligence",
                "content": f"Threat intelligence analysis indicates elevated risk factors with a reputation score of {threat_intelligence.get('reputation_score', 100):.1f}/100. This suggests the organization may already be on the radar of malicious actors or operating in a high-threat environment requiring enhanced vigilance."
            })
        
        # Remediation strategy
        quick_wins = len(self._identify_quick_wins(vulnerabilities))
        if quick_wins > 0:
            storyline.append({
                "section": "Strategic Response",
                "content": f"The remediation strategy should prioritize {quick_wins} quick-win opportunities that provide immediate risk reduction with minimal resource investment. This approach will demonstrate rapid security improvements while more complex vulnerabilities are addressed through a structured remediation program."
            })
        
        # Future outlook
        storyline.append({
            "section": "Forward Outlook",
            "content": "Implementation of the recommended security measures will significantly improve the organization's security posture. Continuous monitoring and regular assessments will ensure sustained protection against evolving threats and maintain stakeholder confidence in the organization's cybersecurity capabilities."
        })
        
        return {
            "executive_storyline": storyline,
            "key_messages": self._extract_key_messages(storyline),
            "board_summary": self._generate_board_summary(risk_assessment, vulnerabilities),
            "media_statement": self._generate_media_statement(risk_assessment)
        }
    
    def _extract_key_messages(self, storyline: List[Dict[str, str]]) -> List[str]:
        """Extract key messages for executive communication"""
        key_messages = []
        
        for section in storyline:
            # Extract first sentence as key message
            content = section["content"]
            first_sentence = content.split('.')[0] + '.'
            key_messages.append(first_sentence)
        
        return key_messages
    
    def _generate_board_summary(self, risk_assessment: Dict[str, Any], 
                              vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Generate board-level summary"""
        return {
            "headline": f"{risk_assessment.get('risk_level', 'UNKNOWN')} cybersecurity risk identified requiring {len(vulnerabilities)} security remediations",
            "financial_impact": self._estimate_financial_impact(vulnerabilities, risk_assessment),
            "timeline": "Immediate action required for critical items, 30-90 day roadmap for comprehensive remediation",
            "resource_approval": "Security team augmentation and specialized expertise recommended",
            "next_board_update": "30 days - Progress report on critical vulnerability remediation"
        }
    
    def _generate_media_statement(self, risk_assessment: Dict[str, Any]) -> str:
        """Generate media statement template"""
        risk_level = risk_assessment.get("risk_level", "UNKNOWN")
        
        if risk_level in ["CRITICAL", "HIGH"]:
            return "The organization has proactively identified security areas for improvement through comprehensive assessment and is implementing enhanced cybersecurity measures to maintain the highest standards of data protection and service availability."
        else:
            return "Regular security assessments continue to validate the organization's strong cybersecurity posture, with ongoing improvements planned to maintain industry-leading security standards."
    
    def _generate_technical_analysis(self, vulnerabilities: List[VulnerabilityContext], 
                                   correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed technical analysis"""
        return {
            "attack_vector_analysis": self._analyze_attack_vectors(vulnerabilities),
            "exploit_difficulty_assessment": self._assess_exploit_difficulty(vulnerabilities),
            "defense_evasion_techniques": self._identify_defense_evasion(vulnerabilities),
            "lateral_movement_opportunities": self._analyze_lateral_movement(vulnerabilities, correlations),
            "data_exfiltration_risks": self._assess_data_exfiltration_risks(vulnerabilities),
            "persistence_mechanisms": self._identify_persistence_mechanisms(vulnerabilities)
        }
    
    def _analyze_attack_vectors(self, vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Analyze attack vectors in detail"""
        vector_analysis = {}
        
        # Group by attack vector
        from collections import defaultdict
        vector_groups = defaultdict(list)
        
        for vuln in vulnerabilities:
            if hasattr(vuln, 'attack_vector'):
                vector_groups[vuln.attack_vector.value].append(vuln)
        
        for vector, vulns in vector_groups.items():
            avg_exploitability = statistics.mean([getattr(v, 'exploitability', 0.5) for v in vulns])
            avg_impact = statistics.mean([getattr(v, 'business_impact', 5.0) for v in vulns])
            
            vector_analysis[vector] = {
                "vulnerability_count": len(vulns),
                "average_exploitability": round(avg_exploitability, 2),
                "average_business_impact": round(avg_impact, 1),
                "risk_score": round(avg_exploitability * avg_impact, 2),
                "common_techniques": self._identify_common_techniques(vulns),
                "mitigation_strategies": self._suggest_vector_mitigations(vector)
            }
        
        return vector_analysis
    
    def _identify_common_techniques(self, vulnerabilities: List[VulnerabilityContext]) -> List[str]:
        """Identify common attack techniques for a vector"""
        techniques = set()
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if "sqli" in template_lower:
                techniques.add("SQL Injection")
            elif "xss" in template_lower:
                techniques.add("Cross-Site Scripting")
            elif "rce" in template_lower:
                techniques.add("Remote Code Execution")
            elif "lfi" in template_lower:
                techniques.add("Local File Inclusion")
            elif "auth" in template_lower:
                techniques.add("Authentication Bypass")
            elif "upload" in template_lower:
                techniques.add("File Upload Attacks")
            
        return list(techniques)[:5]  # Top 5 techniques
    
    def _suggest_vector_mitigations(self, vector: str) -> List[str]:
        """Suggest mitigations for specific attack vectors"""
        mitigation_map = {
            "web_application": [
                "Implement Web Application Firewall (WAF)",
                "Input validation and sanitization",
                "Secure coding practices",
                "Regular security code reviews"
            ],
            "network": [
                "Network segmentation",
                "Intrusion Detection System (IDS)",
                "Firewall rule optimization",
                "Network monitoring and logging"
            ],
            "configuration": [
                "Configuration management tools",
                "Security hardening guidelines",
                "Regular configuration audits",
                "Automated compliance checking"
            ],
            "system": [
                "Patch management program",
                "System hardening",
                "Endpoint detection and response (EDR)",
                "Privilege escalation monitoring"
            ]
        }
        
        return mitigation_map.get(vector, ["General security controls", "Defense in depth strategy"])
    
    def _assess_exploit_difficulty(self, vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Assess overall exploit difficulty"""
        if not vulnerabilities:
            return {"overall_difficulty": "N/A", "analysis": "No vulnerabilities to assess"}
        
        exploitability_scores = [getattr(v, 'exploitability', 0.5) for v in vulnerabilities]
        avg_exploitability = statistics.mean(exploitability_scores)
        
        # Categorize difficulty
        if avg_exploitability > 0.8:
            difficulty = "Very Easy"
            description = "Vulnerabilities can be exploited with minimal effort and readily available tools"
        elif avg_exploitability > 0.6:
            difficulty = "Easy"
            description = "Exploitation requires basic technical skills and common tools"
        elif avg_exploitability > 0.4:
            difficulty = "Moderate"
            description = "Exploitation requires intermediate technical skills and specialized tools"
        elif avg_exploitability > 0.2:
            difficulty = "Difficult"
            description = "Exploitation requires advanced technical skills and custom tools"
        else:
            difficulty = "Very Difficult"
            description = "Exploitation requires expert-level skills and significant time investment"
        
        return {
            "overall_difficulty": difficulty,
            "average_exploitability": round(avg_exploitability, 2),
            "description": description,
            "skill_level_required": self._map_skill_level(avg_exploitability),
            "tools_required": self._identify_required_tools(vulnerabilities)
        }
    
    def _map_skill_level(self, exploitability: float) -> str:
        """Map exploitability to required skill level"""
        if exploitability > 0.8:
            return "Script Kiddie"
        elif exploitability > 0.6:
            return "Novice Attacker"
        elif exploitability > 0.4:
            return "Intermediate Attacker"
        elif exploitability > 0.2:
            return "Advanced Attacker"
        else:
            return "Expert/APT Level"
    
    def _identify_required_tools(self, vulnerabilities: List[VulnerabilityContext]) -> List[str]:
        """Identify tools required for exploitation"""
        tools = set()
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if "sqli" in template_lower:
                tools.update(["SQLMap", "Burp Suite", "Manual SQL injection"])
            elif "xss" in template_lower:
                tools.update(["XSS payloads", "Browser", "BeEF"])
            elif "rce" in template_lower:
                tools.update(["Reverse shells", "Metasploit", "Custom exploits"])
            elif "upload" in template_lower:
                tools.update(["Web shells", "File upload bypasses"])
            else:
                tools.add("Common penetration testing tools")
        
        return list(tools)[:5]  # Top 5 tools
    
    def _identify_defense_evasion(self, vulnerabilities: List[VulnerabilityContext]) -> List[Dict[str, str]]:
        """Identify potential defense evasion techniques"""
        evasion_techniques = []
        
        # Check for vulnerabilities that might enable evasion
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if "log" in template_lower or "audit" in template_lower:
                evasion_techniques.append({
                    "technique": "Log Evasion",
                    "description": "Attackers may exploit logging vulnerabilities to avoid detection",
                    "vulnerability": vuln.template_id
                })
            
            if "auth" in template_lower:
                evasion_techniques.append({
                    "technique": "Authentication Bypass",
                    "description": "Bypass authentication mechanisms to avoid access controls",
                    "vulnerability": vuln.template_id
                })
            
            if "encrypt" in template_lower or "ssl" in template_lower:
                evasion_techniques.append({
                    "technique": "Traffic Encryption Abuse",
                    "description": "Use encrypted channels to hide malicious communications",
                    "vulnerability": vuln.template_id
                })
        
        return evasion_techniques[:5]  # Top 5 techniques
    
    def _analyze_lateral_movement(self, vulnerabilities: List[VulnerabilityContext], 
                                correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze lateral movement opportunities"""
        lateral_movement = {
            "potential_paths": [],
            "network_pivots": [],
            "credential_harvesting": [],
            "service_exploitation": []
        }
        
        # Check for lateral movement enablers
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if any(service in template_lower for service in ["ssh", "rdp", "smb", "winrm"]):
                lateral_movement["network_pivots"].append({
                    "service": vuln.template_id,
                    "target": getattr(vuln, 'target', 'Unknown'),
                    "description": "Network service that could enable lateral movement"
                })
            
            if any(cred in template_lower for cred in ["password", "credential", "token", "session"]):
                lateral_movement["credential_harvesting"].append({
                    "vulnerability": vuln.template_id,
                    "target": getattr(vuln, 'target', 'Unknown'),
                    "description": "Potential credential harvesting opportunity"
                })
        
        # Analyze attack chains for lateral movement
        if correlations.get("attack_chains"):
            for chain in correlations["attack_chains"]:
                if len(chain.get("vulnerabilities", [])) > 1:
                    lateral_movement["potential_paths"].append({
                        "chain_name": chain.get("name", "Unknown"),
                        "target": chain.get("target", "Unknown"),
                        "path_length": len(chain.get("vulnerabilities", [])),
                        "description": f"Multi-step attack path: {' -> '.join(chain.get('vulnerabilities', [])[:3])}"
                    })
        
        return lateral_movement
    
    def _assess_data_exfiltration_risks(self, vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Assess data exfiltration risks"""
        exfiltration_risks = {
            "direct_access": [],
            "database_exposure": [],
            "file_system_access": [],
            "api_exposure": [],
            "overall_risk": "LOW"
        }
        
        high_risk_count = 0
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if any(db in template_lower for db in ["sql", "database", "mysql", "postgres", "mongo"]):
                exfiltration_risks["database_exposure"].append({
                    "vulnerability": vuln.template_id,
                    "target": getattr(vuln, 'target', 'Unknown'),
                    "risk_level": "HIGH"
                })
                high_risk_count += 1
            
            if any(file_term in template_lower for file_term in ["lfi", "directory", "file", "path"]):
                exfiltration_risks["file_system_access"].append({
                    "vulnerability": vuln.template_id,
                    "target": getattr(vuln, 'target', 'Unknown'),
                    "risk_level": "MEDIUM"
                })
            
            if "api" in template_lower:
                exfiltration_risks["api_exposure"].append({
                    "vulnerability": vuln.template_id,
                    "target": getattr(vuln, 'target', 'Unknown'),
                    "risk_level": "MEDIUM"
                })
        
        # Determine overall risk
        if high_risk_count > 2:
            exfiltration_risks["overall_risk"] = "CRITICAL"
        elif high_risk_count > 0:
            exfiltration_risks["overall_risk"] = "HIGH"
        elif any(exfiltration_risks[key] for key in ["file_system_access", "api_exposure"]):
            exfiltration_risks["overall_risk"] = "MEDIUM"
        
        return exfiltration_risks
    
    def _identify_persistence_mechanisms(self, vulnerabilities: List[VulnerabilityContext]) -> List[Dict[str, str]]:
        """Identify potential persistence mechanisms"""
        persistence_mechanisms = []
        
        for vuln in vulnerabilities:
            if not hasattr(vuln, 'template_id'):
                continue
                
            template_lower = vuln.template_id.lower()
            
            if "upload" in template_lower:
                persistence_mechanisms.append({
                    "mechanism": "File Upload Backdoor",
                    "description": "Uploaded malicious files could provide persistent access",
                    "vulnerability": vuln.template_id
                })
            
            if "rce" in template_lower:
                persistence_mechanisms.append({
                    "mechanism": "System-level Persistence",
                    "description": "Code execution could install persistent backdoors",
                    "vulnerability": vuln.template_id
                })
            
            if any(auth in template_lower for auth in ["auth", "session", "login"]):
                persistence_mechanisms.append({
                    "mechanism": "Authentication Persistence",
                    "description": "Compromised authentication could maintain long-term access",
                    "vulnerability": vuln.template_id
                })
        
        return persistence_mechanisms[:5]  # Top 5 mechanisms
    
    def _analyze_attack_surface(self, recon_results: Dict[str, Any], 
                              vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Analyze the overall attack surface"""
        # Calculate attack surface metrics
        total_targets = len(recon_results)
        total_services = sum(len(data.get("open_ports", [])) for data in recon_results.values())
        total_web_services = sum(len(data.get("http_info", [])) for data in recon_results.values())
        
        # Vulnerability distribution across attack surface
        target_vulnerability_map = defaultdict(int)
        for vuln in vulnerabilities:
            if hasattr(vuln, 'target'):
                target_vulnerability_map[vuln.target] += 1
        
        # Identify high-risk targets
        high_risk_targets = [
            {"target": target, "vulnerability_count": count}
            for target, count in target_vulnerability_map.items()
            if count >= 3
        ]
        
        return {
            "surface_metrics": {
                "total_targets": total_targets,
                "total_services": total_services,
                "web_services": total_web_services,
                "vulnerability_density": len(vulnerabilities) / max(total_targets, 1)
            },
            "high_risk_targets": sorted(high_risk_targets, key=lambda x: x["vulnerability_count"], reverse=True)[:10],
            "service_exposure": self._analyze_service_exposure(recon_results),
            "attack_surface_evolution": self._estimate_surface_evolution(recon_results, vulnerabilities)
        }
    
    def _analyze_service_exposure(self, recon_results: Dict[str, Any]) -> Dict[str, int]:
        """Analyze service exposure across the attack surface"""
        service_counts = defaultdict(int)
        
        for target, data in recon_results.items():
            for port_info in data.get("open_ports", []):
                port = port_info.get("port", 0)
                
                # Map common ports to services
                if port == 80:
                    service_counts["HTTP"] += 1
                elif port == 443:
                    service_counts["HTTPS"] += 1
                elif port == 22:
                    service_counts["SSH"] += 1
                elif port == 21:
                    service_counts["FTP"] += 1
                elif port == 25:
                    service_counts["SMTP"] += 1
                elif port == 53:
                    service_counts["DNS"] += 1
                elif port in [3389, 5985, 5986]:
                    service_counts["Remote Management"] += 1
                else:
                    service_counts["Other"] += 1
        
        return dict(service_counts)
    
    def _estimate_surface_evolution(self, recon_results: Dict[str, Any], 
                                  vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Estimate how the attack surface might evolve"""
        return {
            "growth_indicators": [
                "New service deployments",
                "Additional subdomain discovery",
                "Cloud service expansion"
            ],
            "risk_amplification_factors": [
                "Unpatched vulnerabilities becoming exploitable",
                "New vulnerability disclosures",
                "Increased attacker interest in identified targets"
            ],
            "monitoring_recommendations": [
                "Continuous subdomain monitoring",
                "Port scan monitoring",
                "SSL certificate transparency monitoring",
                "Cloud asset discovery"
            ]
        }
    
    def _perform_temporal_analysis(self, vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Perform temporal analysis of vulnerabilities"""
        # Note: In a real implementation, this would analyze vulnerability ages,
        # patch availability timelines, and historical exploit data
        
        return {
            "vulnerability_age_analysis": {
                "average_days_unpatched": "Analysis requires vulnerability disclosure dates",
                "oldest_vulnerability": "Requires CVE date analysis",
                "newest_vulnerability": "Requires recent disclosure tracking"
            },
            "patch_availability": {
                "patches_available": "Requires vendor patch tracking",
                "patch_complexity": "Requires remediation analysis",
                "zero_day_indicators": "Requires threat intelligence correlation"
            },
            "exploit_timeline": {
                "public_exploits": "Requires exploit database correlation",
                "weaponization_risk": "Requires threat landscape analysis",
                "attacker_interest": "Requires dark web monitoring"
            },
            "recommendation": "Implement vulnerability age tracking and patch management metrics for improved temporal analysis"
        }
    
    def _generate_remediation_roadmap(self, vulnerabilities: List[VulnerabilityContext], 
                                    risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive remediation roadmap"""
        # Get prioritized vulnerabilities
        priority_list = risk_assessment.get("remediation_priority", [])
        
        # Create time-based roadmap
        roadmap = {
            "immediate_actions": {
                "timeline": "0-24 hours",
                "actions": [],
                "success_criteria": "Critical vulnerabilities patched or mitigated"
            },
            "short_term": {
                "timeline": "1-7 days", 
                "actions": [],
                "success_criteria": "High-severity vulnerabilities addressed"
            },
            "medium_term": {
                "timeline": "1-4 weeks",
                "actions": [],
                "success_criteria": "Medium-severity vulnerabilities resolved"
            },
            "long_term": {
                "timeline": "1-3 months",
                "actions": [],
                "success_criteria": "All vulnerabilities addressed, process improvements implemented"
            }
        }
        
        # Categorize actions by timeline
        for item in priority_list[:20]:  # Top 20 priorities
            priority_score = item.get("priority_score", 0)
            
            action = {
                "vulnerability": item.get("template_id", "Unknown"),
                "target": item.get("target", "Unknown"),
                "effort": item.get("estimated_effort", "Unknown"),
                "justification": item.get("business_justification", "")
            }
            
            if priority_score >= 8.0:
                roadmap["immediate_actions"]["actions"].append(action)
            elif priority_score >= 6.0:
                roadmap["short_term"]["actions"].append(action)
            elif priority_score >= 4.0:
                roadmap["medium_term"]["actions"].append(action)
            else:
                roadmap["long_term"]["actions"].append(action)
        
        # Add strategic initiatives
        roadmap["strategic_initiatives"] = {
            "security_program_improvements": [
                "Implement continuous vulnerability monitoring",
                "Enhance patch management processes",
                "Improve security awareness training",
                "Establish security metrics and reporting"
            ],
            "technology_improvements": [
                "Deploy additional security controls",
                "Upgrade vulnerable components",
                "Implement security automation",
                "Enhance logging and monitoring"
            ]
        }
        
        return roadmap
    
    def _generate_compliance_assessment(self, vulnerabilities: List[VulnerabilityContext], 
                                      risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance assessment"""
        compliance_impact = risk_assessment.get("compliance_impact", [])
        business_context = self._create_business_context()
        
        assessment = {
            "frameworks_assessed": business_context.compliance_requirements,
            "compliance_violations": compliance_impact,
            "overall_compliance_risk": "LOW",
            "recommendations": []
        }
        
        # Determine overall compliance risk
        if len(compliance_impact) >= 3:
            assessment["overall_compliance_risk"] = "HIGH"
        elif len(compliance_impact) >= 1:
            assessment["overall_compliance_risk"] = "MEDIUM"
        
        # Generate framework-specific recommendations
        for framework in business_context.compliance_requirements:
            if framework == "GDPR":
                assessment["recommendations"].extend([
                    "Conduct Data Protection Impact Assessment (DPIA)",
                    "Review data processing activities",
                    "Enhance breach notification procedures"
                ])
            elif framework == "SOX":
                assessment["recommendations"].extend([
                    "Review IT general controls",
                    "Document remediation activities",
                    "Implement change management controls"
                ])
            elif framework == "HIPAA":
                assessment["recommendations"].extend([
                    "Conduct security risk assessment",
                    "Review access controls for PHI",
                    "Update security policies and procedures"
                ])
        
        return assessment
    
    def _generate_strategic_recommendations(self, risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate strategic-level recommendations"""
        recommendations = []
        
        risk_level = risk_assessment.get("risk_level", "UNKNOWN")
        
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.extend([
                "Establish incident response team and procedures",
                "Implement continuous security monitoring",
                "Consider cyber insurance coverage review",
                "Engage external security consulting for high-risk areas"
            ])
        
        recommendations.extend([
            "Develop comprehensive cybersecurity strategy",
            "Implement security awareness training program",
            "Establish regular penetration testing schedule",
            "Create security metrics and KPI dashboard",
            "Develop vendor security assessment program",
            "Implement DevSecOps practices",
            "Establish bug bounty or responsible disclosure program"
        ])
        
        return recommendations
    
    def _generate_monitoring_recommendations(self, vulnerabilities: List[VulnerabilityContext]) -> List[str]:
        """Generate monitoring and detection recommendations"""
        recommendations = [
            "Implement continuous vulnerability scanning",
            "Deploy Security Information and Event Management (SIEM)",
            "Establish baseline network traffic monitoring",
            "Implement file integrity monitoring",
            "Deploy endpoint detection and response (EDR) solutions"
        ]
        
        # Add specific recommendations based on vulnerability types
        vuln_types = set()
        for vuln in vulnerabilities:
            if hasattr(vuln, 'template_id'):
                template_lower = vuln.template_id.lower()
                if "sql" in template_lower:
                    vuln_types.add("database")
                elif "xss" in template_lower:
                    vuln_types.add("web")
                elif "auth" in template_lower:
                    vuln_types.add("authentication")
        
        if "database" in vuln_types:
            recommendations.append("Implement database activity monitoring (DAM)")
        
        if "web" in vuln_types:
            recommendations.append("Deploy Web Application Firewall (WAF) with logging")
        
        if "authentication" in vuln_types:
            recommendations.append("Implement privileged access management (PAM)")
        
        return recommendations
    
    def _calculate_analysis_confidence(self, vulnerabilities: List[VulnerabilityContext]) -> Dict[str, Any]:
        """Calculate confidence in the analysis"""
        if not vulnerabilities:
            return {"overall_confidence": "N/A", "analysis": "No vulnerabilities to assess"}
        
        # Calculate average confidence
        confidence_scores = [getattr(v, 'confidence', 0.8) for v in vulnerabilities if hasattr(v, 'confidence')]
        
        if confidence_scores:
            avg_confidence = statistics.mean(confidence_scores)
            confidence_level = "HIGH" if avg_confidence > 0.8 else "MEDIUM" if avg_confidence > 0.6 else "LOW"
        else:
            avg_confidence = 0.8  # Default
            confidence_level = "MEDIUM"
        
        return {
            "overall_confidence": confidence_level,
            "average_score": round(avg_confidence, 2),
            "high_confidence_findings": len([s for s in confidence_scores if s > 0.8]),
            "factors_affecting_confidence": [
                "Template validation quality",
                "Response pattern analysis",
                "False positive filtering effectiveness",
                "Threat intelligence correlation accuracy"
            ]
        }
    
    def _document_methodology(self) -> Dict[str, Any]:
        """Document the analysis methodology"""
        return {
            "analysis_framework": "Bl4ckC3ll_PANTHEON Enhanced Intelligence Engine v9.0.0",
            "components_used": {
                "intelligent_analyzer": self.enable_deep_analysis,
                "risk_calculator": True,
                "correlation_engine": self.enable_correlation,
                "threat_intelligence": self.enable_threat_intel,
                "narrative_generation": self.narrative_generation
            },
            "risk_calculation_methodology": {
                "business_context_weighting": "70% business impact, 30% likelihood",
                "cvss_scoring": "Calculated based on severity and template characteristics",
                "exploitability_assessment": "Based on available tools and complexity",
                "correlation_analysis": "Multi-dimensional vulnerability relationship mapping"
            },
            "threat_intelligence_sources": [
                "Simulated threat feed analysis",
                "Vulnerability pattern correlation",
                "Attack vector assessment",
                "Business context integration"
            ],
            "limitations": [
                "Analysis based on automated scanning results",
                "Manual verification recommended for critical findings",
                "Threat intelligence simulation pending real API integration",
                "Business context requires organization-specific configuration"
            ]
        }
    
    def _generate_fallback_report(self, run_dir: Path, recon_results: Dict[str, Any], 
                                vuln_results: Dict[str, Any], targets: List[str]) -> Dict[str, Any]:
        """Generate fallback report if enhanced analysis fails"""
        self.logger.warning("Generating fallback report due to analysis failure")
        
        return {
            "report_metadata": {
                "run_id": run_dir.name,
                "generation_timestamp": datetime.now().isoformat(),
                "analysis_engine_version": "9.0.0-fallback",
                "targets_analyzed": targets,
                "analysis_status": "FALLBACK_MODE"
            },
            "executive_summary": {
                "message": "Basic report generated due to enhanced analysis failure",
                "targets_scanned": len(targets),
                "recon_data_available": bool(recon_results),
                "vulnerability_data_available": bool(vuln_results)
            },
            "raw_data": {
                "recon_results": recon_results,
                "vulnerability_results": vuln_results
            },
            "recommendations": [
                "Review enhanced analysis configuration",
                "Check system logs for analysis errors",
                "Contact support for assistance with intelligent reporting"
            ]
        }


def atomic_write(file_path: Path, content: str) -> bool:
    """Atomic write operation for safe file writing"""
    try:
        temp_path = file_path.with_suffix('.tmp')
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        temp_path.rename(file_path)
        return True
    except Exception as e:
        logging.error(f"Atomic write failed for {file_path}: {e}")
        return False


# Import defaultdict for the code
from collections import defaultdict