#!/usr/bin/env python3
"""
Intelligent Report Engine for Bl4ckC3ll_PANTHEON
Advanced security analysis with deep thinking and intelligent processing

Author: @cxb3rf1lth
"""

import hashlib
import json
import logging
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class ThreatLevel(Enum):
    """Threat level enumeration with numerical values for calculations"""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFORMATIONAL = 1


class AttackVector(Enum):
    """Attack vector categories for vulnerability classification"""

    NETWORK = "network"
    WEB_APPLICATION = "web_application"
    SYSTEM = "system"
    CONFIGURATION = "configuration"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"


@dataclass
class VulnerabilityContext:
    """Enhanced vulnerability context with intelligent analysis"""

    id: str
    name: str
    severity: str
    description: str
    template_id: str
    target: str
    attack_vector: AttackVector
    cvss_score: float
    exploitability: float
    confidence: float
    business_impact: float
    remediation_complexity: int  # 1-5 scale
    public_exploit_available: bool
    threat_intelligence: Dict[str, Any]
    related_vulnerabilities: List[str]
    attack_chain_position: int  # Position in potential attack chain


@dataclass
class ThreatIntelligence:
    """Aggregated threat intelligence data"""

    reputation_score: float  # 0-100, lower is worse
    known_malicious_ips: List[str]
    suspicious_domains: List[str]
    threat_feeds: Dict[str, Any]
    geolocation_risks: Dict[str, float]
    dark_web_mentions: int
    recent_campaigns: List[Dict[str, Any]]


@dataclass
class BusinessContext:
    """Business context for risk assessment"""

    asset_criticality: float  # 1-10 scale
    data_sensitivity: float  # 1-10 scale
    availability_requirement: float  # 1-10 scale
    compliance_requirements: List[str]
    business_hours_impact: float
    revenue_impact_per_hour: float


class IntelligentReportAnalyzer:
    """Advanced report analyzer with deep thinking capabilities"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.vulnerability_patterns = {}
        self.attack_signatures = {}
        self.false_positive_patterns = []
        self.threat_landscape = {}

        # Initialize intelligence databases
        self._initialize_intelligence_db()

    def _initialize_intelligence_db(self):
        """Initialize threat intelligence and vulnerability pattern databases"""
        # Common false positive patterns
        self.false_positive_patterns = [
            r"tech-detect-.*",
            r".*-version-detect",
            r".*-info-disclosure",
            r".*-default-page",
            r".*-status-page",
        ]

        # Attack vector mapping
        self.attack_vector_mapping = {
            "sqli": AttackVector.WEB_APPLICATION,
            "xss": AttackVector.WEB_APPLICATION,
            "rce": AttackVector.WEB_APPLICATION,
            "lfi": AttackVector.WEB_APPLICATION,
            "rfi": AttackVector.WEB_APPLICATION,
            "ssrf": AttackVector.WEB_APPLICATION,
            "xxe": AttackVector.WEB_APPLICATION,
            "upload": AttackVector.WEB_APPLICATION,
            "auth-bypass": AttackVector.WEB_APPLICATION,
            "cors": AttackVector.WEB_APPLICATION,
            "csp": AttackVector.WEB_APPLICATION,
            "ssl": AttackVector.NETWORK,
            "tls": AttackVector.NETWORK,
            "ssh": AttackVector.NETWORK,
            "ftp": AttackVector.NETWORK,
            "smtp": AttackVector.NETWORK,
            "dns": AttackVector.NETWORK,
            "config": AttackVector.CONFIGURATION,
            "default": AttackVector.CONFIGURATION,
            "exposed": AttackVector.CONFIGURATION,
            "backup": AttackVector.CONFIGURATION,
            "debug": AttackVector.CONFIGURATION,
        }

    def analyze_vulnerability_intelligence(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[VulnerabilityContext]:
        """Apply intelligent analysis to vulnerability data"""
        enhanced_vulns = []

        for vuln in vulnerabilities:
            try:
                context = self._create_vulnerability_context(vuln)
                enhanced_vulns.append(context)
            except Exception as e:
                self.logger.warning(f"Failed to analyze vulnerability: {e}")

        # Apply correlation analysis
        enhanced_vulns = self._correlate_vulnerabilities(enhanced_vulns)

        return enhanced_vulns

    def _create_vulnerability_context(
        self, vuln: Dict[str, Any]
    ) -> VulnerabilityContext:
        """Create enhanced vulnerability context with intelligent analysis"""
        info = vuln.get("info", {})
        template_id = vuln.get("template-id", "unknown")

        # Determine attack vector
        attack_vector = self._determine_attack_vector(template_id)

        # Calculate CVSS score if not available
        cvss_score = self._calculate_cvss_score(vuln)

        # Calculate exploitability
        exploitability = self._calculate_exploitability(vuln)

        # Calculate confidence score
        confidence = self._calculate_confidence_score(vuln)

        # Calculate business impact
        business_impact = self._calculate_business_impact(vuln)

        # Determine remediation complexity
        remediation_complexity = self._calculate_remediation_complexity(vuln)

        # Check for public exploits
        public_exploit_available = self._check_public_exploits(template_id)

        # Gather threat intelligence
        threat_intel = self._gather_threat_intelligence(vuln)

        return VulnerabilityContext(
            id=hashlib.md5(
                f"{template_id}_{vuln.get('matched-at', '')}".encode()
            ).hexdigest(),
            name=info.get("name", "Unknown Vulnerability"),
            severity=info.get("severity", "unknown"),
            description=info.get("description", ""),
            template_id=template_id,
            target=vuln.get("matched-at", ""),
            attack_vector=attack_vector,
            cvss_score=cvss_score,
            exploitability=exploitability,
            confidence=confidence,
            business_impact=business_impact,
            remediation_complexity=remediation_complexity,
            public_exploit_available=public_exploit_available,
            threat_intelligence=threat_intel,
            related_vulnerabilities=[],
            attack_chain_position=0,
        )

    def _determine_attack_vector(self, template_id: str) -> AttackVector:
        """Intelligently determine the attack vector based on template ID"""
        template_lower = template_id.lower()

        for pattern, vector in self.attack_vector_mapping.items():
            if pattern in template_lower:
                return vector

        return AttackVector.WEB_APPLICATION  # Default

    def _calculate_cvss_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate CVSS score based on vulnerability characteristics"""
        info = vuln.get("info", {})
        severity = info.get("severity", "unknown").lower()

        # Base CVSS scores by severity
        base_scores = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 1.0,
            "unknown": 2.0,
        }

        base_score = base_scores.get(severity, 2.0)

        # Adjust based on template characteristics
        template_id = vuln.get("template-id", "")

        if "rce" in template_id.lower():
            base_score = min(base_score + 2.0, 10.0)
        elif "sqli" in template_id.lower():
            base_score = min(base_score + 1.5, 10.0)
        elif "xss" in template_id.lower():
            base_score = min(base_score + 1.0, 10.0)
        elif "auth-bypass" in template_id.lower():
            base_score = min(base_score + 1.8, 10.0)

        return round(base_score, 1)

    def _calculate_exploitability(self, vuln: Dict[str, Any]) -> float:
        """Calculate exploitability score (0-1)"""
        template_id = vuln.get("template-id", "").lower()

        # Base exploitability
        exploitability = 0.5

        # High exploitability indicators
        if any(
            pattern in template_id
            for pattern in ["rce", "sqli", "auth-bypass", "upload"]
        ):
            exploitability += 0.3

        # Network accessibility
        if "exposed" in template_id or "public" in template_id:
            exploitability += 0.2

        # Low exploitability indicators
        if any(pattern in template_id for pattern in ["info", "detect", "version"]):
            exploitability -= 0.3

        return max(0.0, min(1.0, exploitability))

    def _calculate_confidence_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate confidence score for vulnerability (0-1)"""
        template_id = vuln.get("template-id", "")

        # Start with base confidence
        confidence = 0.8

        # Reduce confidence for common false positives
        for pattern in self.false_positive_patterns:
            if re.match(pattern, template_id):
                confidence *= 0.4
                break

        # Increase confidence for well-validated templates
        if template_id.startswith("CVE-"):
            confidence = min(confidence * 1.3, 1.0)

        # Check response patterns for verification
        response = vuln.get("response", "")
        if response and any(
            indicator in response.lower()
            for indicator in ["error", "exception", "sql", "root:"]
        ):
            confidence = min(confidence * 1.2, 1.0)

        return round(confidence, 2)

    def _calculate_business_impact(self, vuln: Dict[str, Any]) -> float:
        """Calculate potential business impact (0-10 scale)"""
        template_id = vuln.get("template-id", "").lower()
        severity = vuln.get("info", {}).get("severity", "unknown").lower()

        # Base impact by severity
        impact_mapping = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0,
        }

        base_impact = impact_mapping.get(severity, 2.0)

        # Adjust based on vulnerability type
        if "rce" in template_id:
            base_impact = min(base_impact + 2.0, 10.0)
        elif "auth-bypass" in template_id:
            base_impact = min(base_impact + 1.8, 10.0)
        elif "sqli" in template_id:
            base_impact = min(base_impact + 1.5, 10.0)
        elif "data" in template_id or "leak" in template_id:
            base_impact = min(base_impact + 1.3, 10.0)

        return round(base_impact, 1)

    def _calculate_remediation_complexity(self, vuln: Dict[str, Any]) -> int:
        """Calculate remediation complexity (1-5 scale, 5 being most complex)"""
        template_id = vuln.get("template-id", "").lower()

        # Default complexity
        complexity = 2

        # High complexity scenarios
        if any(
            pattern in template_id for pattern in ["ssl", "tls", "crypto", "design"]
        ):
            complexity = 4
        elif any(pattern in template_id for pattern in ["auth", "session", "cors"]):
            complexity = 3
        elif any(pattern in template_id for pattern in ["config", "header", "default"]):
            complexity = 2
        elif any(pattern in template_id for pattern in ["patch", "update", "version"]):
            complexity = 1

        return max(1, min(5, complexity))

    def _check_public_exploits(self, template_id: str) -> bool:
        """Check if public exploits are available for this vulnerability"""
        # This would typically query exploit databases
        # For now, use heuristics based on template ID

        exploit_indicators = ["cve-", "rce", "sqli", "upload", "deserial"]
        return any(indicator in template_id.lower() for indicator in exploit_indicators)

    def _gather_threat_intelligence(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Gather threat intelligence for vulnerability"""
        # This would typically query multiple threat intelligence sources
        # For now, return basic intelligence based on vulnerability characteristics

        template_id = vuln.get("template-id", "")

        intelligence = {
            "threat_feeds": {},
            "exploit_availability": self._check_public_exploits(template_id),
            "attack_frequency": self._estimate_attack_frequency(template_id),
            "attribution": [],
            "iocs": [],
        }

        return intelligence

    def _estimate_attack_frequency(self, template_id: str) -> str:
        """Estimate how frequently this vulnerability type is attacked"""
        template_lower = template_id.lower()

        if any(pattern in template_lower for pattern in ["sqli", "xss", "rce"]):
            return "very_high"
        elif any(
            pattern in template_lower for pattern in ["upload", "auth-bypass", "lfi"]
        ):
            return "high"
        elif any(pattern in template_lower for pattern in ["csrf", "cors", "ssrf"]):
            return "medium"
        else:
            return "low"

    def _correlate_vulnerabilities(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[VulnerabilityContext]:
        """Apply correlation analysis to identify related vulnerabilities"""
        # Group by target
        target_groups = defaultdict(list)
        for vuln in vulnerabilities:
            target_groups[vuln.target].append(vuln)

        # Find correlations within each target
        for target, vulns in target_groups.items():
            self._find_attack_chains(vulns)
            self._identify_related_vulnerabilities(vulns)

        return vulnerabilities

    def _find_attack_chains(self, vulnerabilities: List[VulnerabilityContext]):
        """Identify potential attack chains"""
        # Sort by exploitability and impact
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.exploitability * v.business_impact,
            reverse=True,
        )

        for i, vuln in enumerate(sorted_vulns):
            vuln.attack_chain_position = i + 1

    def _identify_related_vulnerabilities(
        self, vulnerabilities: List[VulnerabilityContext]
    ):
        """Identify relationships between vulnerabilities"""
        for i, vuln1 in enumerate(vulnerabilities):
            related = []
            for j, vuln2 in enumerate(vulnerabilities):
                if i != j and self._are_vulnerabilities_related(vuln1, vuln2):
                    related.append(vuln2.id)
            vuln1.related_vulnerabilities = related

    def _are_vulnerabilities_related(
        self, vuln1: VulnerabilityContext, vuln2: VulnerabilityContext
    ) -> bool:
        """Check if two vulnerabilities are related"""
        # Same attack vector
        if vuln1.attack_vector == vuln2.attack_vector:
            return True

        # Similar template patterns
        if self._templates_similar(vuln1.template_id, vuln2.template_id):
            return True

        # Complementary vulnerabilities (e.g., auth bypass + privilege escalation)
        complementary_pairs = [
            ("auth-bypass", "privilege"),
            ("upload", "rce"),
            ("lfi", "rce"),
            ("sqli", "privilege"),
        ]

        for pair in complementary_pairs:
            if (
                pair[0] in vuln1.template_id.lower()
                and pair[1] in vuln2.template_id.lower()
            ) or (
                pair[1] in vuln1.template_id.lower()
                and pair[0] in vuln2.template_id.lower()
            ):
                return True

        return False

    def _templates_similar(self, template1: str, template2: str) -> bool:
        """Check if two templates are similar"""
        # Extract base patterns
        pattern1 = re.sub(r"-\d+$", "", template1.lower())
        pattern2 = re.sub(r"-\d+$", "", template2.lower())

        return pattern1 == pattern2


class AdvancedRiskCalculator:
    """Advanced risk calculation with contextual threat modeling"""

    def __init__(self, business_context: Optional[BusinessContext] = None):
        self.business_context = business_context or self._default_business_context()
        self.logger = logging.getLogger(__name__)

    def _default_business_context(self) -> BusinessContext:
        """Create default business context"""
        return BusinessContext(
            asset_criticality=5.0,
            data_sensitivity=5.0,
            availability_requirement=5.0,
            compliance_requirements=["GDPR", "SOX"],
            business_hours_impact=1.0,
            revenue_impact_per_hour=1000.0,
        )

    def calculate_contextual_risk(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> Dict[str, Any]:
        """Calculate risk with business context"""
        if not vulnerabilities:
            return self._empty_risk_assessment()

        # Group vulnerabilities by severity and attack vector
        severity_groups = defaultdict(list)
        vector_groups = defaultdict(list)

        for vuln in vulnerabilities:
            severity_groups[vuln.severity.lower()].append(vuln)
            vector_groups[vuln.attack_vector].append(vuln)

        # Calculate base risk metrics
        base_risk = self._calculate_base_risk(severity_groups)

        # Apply business context multipliers
        contextual_risk = self._apply_business_context(base_risk, vulnerabilities)

        # Calculate attack vector distribution
        vector_distribution = self._calculate_vector_distribution(vector_groups)

        # Identify critical attack paths
        critical_paths = self._identify_critical_attack_paths(vulnerabilities)

        # Generate risk insights
        insights = self._generate_risk_insights(vulnerabilities, contextual_risk)

        return {
            "overall_risk_score": contextual_risk["total_score"],
            "risk_level": contextual_risk["risk_level"],
            "business_impact_score": contextual_risk["business_impact"],
            "likelihood_score": contextual_risk["likelihood"],
            "severity_breakdown": {
                sev: len(vulns) for sev, vulns in severity_groups.items()
            },
            "attack_vector_distribution": vector_distribution,
            "critical_attack_paths": critical_paths,
            "time_to_compromise": self._estimate_time_to_compromise(vulnerabilities),
            "remediation_priority": self._calculate_remediation_priority(
                vulnerabilities
            ),
            "compliance_impact": self._assess_compliance_impact(vulnerabilities),
            "risk_insights": insights,
            "recommendations": self._generate_contextual_recommendations(
                vulnerabilities, contextual_risk
            ),
        }

    def _empty_risk_assessment(self) -> Dict[str, Any]:
        """Return empty risk assessment"""
        return {
            "overall_risk_score": 0,
            "risk_level": "MINIMAL",
            "business_impact_score": 0,
            "likelihood_score": 0,
            "severity_breakdown": {},
            "attack_vector_distribution": {},
            "critical_attack_paths": [],
            "time_to_compromise": "N/A",
            "remediation_priority": [],
            "compliance_impact": [],
            "risk_insights": [],
            "recommendations": [
                "No vulnerabilities detected",
                "Continue regular security monitoring",
            ],
        }

    def _calculate_base_risk(
        self, severity_groups: Dict[str, List[VulnerabilityContext]]
    ) -> Dict[str, float]:
        """Calculate base risk scores"""
        severity_weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 2.0,
            "info": 0.5,
            "informational": 0.5,
            "unknown": 1.0,
        }

        total_score = 0
        for severity, vulns in severity_groups.items():
            weight = severity_weights.get(severity, 1.0)
            # Apply diminishing returns for multiple vulnerabilities of same severity
            count_factor = (
                min(len(vulns), 10) + (len(vulns) - 10) * 0.1
                if len(vulns) > 10
                else len(vulns)
            )
            total_score += weight * count_factor

        return {
            "total_score": total_score,
            "normalized_score": min(total_score / 100.0, 1.0) * 10.0,
        }

    def _apply_business_context(
        self, base_risk: Dict[str, float], vulnerabilities: List[VulnerabilityContext]
    ) -> Dict[str, Any]:
        """Apply business context to risk calculation"""
        base_score = base_risk["total_score"]

        # Calculate business impact multiplier
        impact_multiplier = (
            self.business_context.asset_criticality
            + self.business_context.data_sensitivity
            + self.business_context.availability_requirement
        ) / 30.0  # Normalize to 0-1

        # Calculate likelihood based on exploitability
        avg_exploitability = (
            statistics.mean([v.exploitability for v in vulnerabilities])
            if vulnerabilities
            else 0
        )

        # Apply context
        business_impact = base_score * impact_multiplier
        likelihood = avg_exploitability * 10.0

        # Calculate final risk score
        risk_score = (business_impact * 0.7) + (likelihood * 0.3)

        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "total_score": round(risk_score, 1),
            "business_impact": round(business_impact, 1),
            "likelihood": round(likelihood, 1),
            "risk_level": risk_level,
            "impact_multiplier": round(impact_multiplier, 2),
        }

    def _calculate_vector_distribution(
        self, vector_groups: Dict[AttackVector, List[VulnerabilityContext]]
    ) -> Dict[str, Any]:
        """Calculate attack vector distribution"""
        total_vulns = sum(len(vulns) for vulns in vector_groups.values())

        if total_vulns == 0:
            return {}

        distribution = {}
        for vector, vulns in vector_groups.items():
            distribution[vector.value] = {
                "count": len(vulns),
                "percentage": round((len(vulns) / total_vulns) * 100, 1),
                "risk_score": (
                    sum(v.cvss_score for v in vulns) / len(vulns) if vulns else 0
                ),
            }

        return distribution

    def _identify_critical_attack_paths(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Identify critical attack paths"""
        paths = []

        # Group by target
        target_groups = defaultdict(list)
        for vuln in vulnerabilities:
            target_groups[vuln.target].append(vuln)

        for target, vulns in target_groups.items():
            # Find high-impact paths
            high_impact_vulns = [
                v for v in vulns if v.business_impact >= 7.0 and v.exploitability >= 0.6
            ]

            if high_impact_vulns:
                path = {
                    "target": target,
                    "path_risk": max(
                        v.business_impact * v.exploitability for v in high_impact_vulns
                    ),
                    "vulnerabilities": [v.template_id for v in high_impact_vulns],
                    "estimated_effort": (
                        "Low"
                        if any(v.exploitability > 0.8 for v in high_impact_vulns)
                        else "Medium"
                    ),
                    "potential_impact": (
                        "High"
                        if any(v.business_impact > 8.0 for v in high_impact_vulns)
                        else "Medium"
                    ),
                }
                paths.append(path)

        return sorted(paths, key=lambda p: p["path_risk"], reverse=True)[:5]

    def _estimate_time_to_compromise(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> str:
        """Estimate time to compromise based on vulnerability characteristics"""
        if not vulnerabilities:
            return "N/A"

        # Find fastest attack path
        min_complexity = min(v.remediation_complexity for v in vulnerabilities)
        max_exploitability = max(v.exploitability for v in vulnerabilities)

        if max_exploitability > 0.8 and min_complexity <= 2:
            return "Minutes to Hours"
        elif max_exploitability > 0.6 and min_complexity <= 3:
            return "Hours to Days"
        elif max_exploitability > 0.4:
            return "Days to Weeks"
        else:
            return "Weeks to Months"

    def _calculate_remediation_priority(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Calculate remediation priority"""
        priority_list = []

        for vuln in vulnerabilities:
            priority_score = (
                vuln.business_impact * 0.4
                + vuln.exploitability * 10.0 * 0.3
                + (6 - vuln.remediation_complexity) * 2.0 * 0.2
                + vuln.confidence * 10.0 * 0.1
            )

            priority_list.append(
                {
                    "vulnerability_id": vuln.id,
                    "template_id": vuln.template_id,
                    "target": vuln.target,
                    "priority_score": round(priority_score, 2),
                    "estimated_effort": self._effort_mapping(
                        vuln.remediation_complexity
                    ),
                    "business_justification": self._generate_business_justification(
                        vuln
                    ),
                }
            )

        return sorted(priority_list, key=lambda x: x["priority_score"], reverse=True)

    def _effort_mapping(self, complexity: int) -> str:
        """Map complexity to effort estimate"""
        mapping = {1: "Low", 2: "Low-Medium", 3: "Medium", 4: "Medium-High", 5: "High"}
        return mapping.get(complexity, "Medium")

    def _generate_business_justification(self, vuln: VulnerabilityContext) -> str:
        """Generate business justification for remediation"""
        if vuln.business_impact >= 8.0:
            return f"Critical business asset exposure with potential revenue impact of ${self.business_context.revenue_impact_per_hour:.0f}/hour"
        elif vuln.business_impact >= 6.0:
            return f"High business impact affecting {vuln.attack_vector.value} security"
        elif vuln.exploitability >= 0.8:
            return "High exploitability with available attack tools"
        else:
            return "Reduces overall security posture"

    def _assess_compliance_impact(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Assess compliance impact"""
        compliance_impact = []

        # Check against common compliance requirements
        for compliance in self.business_context.compliance_requirements:
            affected_vulns = []

            for vuln in vulnerabilities:
                if self._affects_compliance(vuln, compliance):
                    affected_vulns.append(vuln.template_id)

            if affected_vulns:
                compliance_impact.append(
                    {
                        "framework": compliance,
                        "affected_vulnerabilities": affected_vulns,
                        "severity": "High" if len(affected_vulns) > 5 else "Medium",
                        "potential_violations": self._get_potential_violations(
                            compliance, affected_vulns
                        ),
                    }
                )

        return compliance_impact

    def _affects_compliance(self, vuln: VulnerabilityContext, compliance: str) -> bool:
        """Check if vulnerability affects compliance"""
        compliance_mappings = {
            "GDPR": ["data", "leak", "exposure", "privacy"],
            "SOX": ["auth", "access", "financial", "audit"],
            "HIPAA": ["data", "health", "privacy", "encryption"],
            "PCI-DSS": ["payment", "card", "crypto", "ssl", "tls"],
        }

        keywords = compliance_mappings.get(compliance, [])
        return any(
            keyword in vuln.template_id.lower() or keyword in vuln.description.lower()
            for keyword in keywords
        )

    def _get_potential_violations(
        self, compliance: str, vulnerabilities: List[str]
    ) -> List[str]:
        """Get potential compliance violations"""
        violation_mappings = {
            "GDPR": [
                "Article 32 - Security of processing",
                "Article 25 - Data protection by design",
            ],
            "SOX": ["Section 404 - Management assessment of internal controls"],
            "HIPAA": [
                "Security Rule - Access Control",
                "Security Rule - Transmission Security",
            ],
            "PCI-DSS": [
                "Requirement 6 - Secure Systems",
                "Requirement 4 - Encrypt Data",
            ],
        }

        return violation_mappings.get(compliance, ["General security requirements"])

    def _generate_risk_insights(
        self, vulnerabilities: List[VulnerabilityContext], risk_context: Dict[str, Any]
    ) -> List[str]:
        """Generate intelligent risk insights"""
        insights = []

        if not vulnerabilities:
            insights.append(
                "🟢 No vulnerabilities detected - maintain current security posture"
            )
            return insights

        # Attack surface analysis
        unique_targets = len(set(v.target for v in vulnerabilities))
        if unique_targets > 5:
            insights.append(
                f"🔍 Large attack surface detected: {unique_targets} unique targets identified"
            )

        # Critical vulnerability insights
        critical_vulns = [
            v for v in vulnerabilities if v.severity.lower() == "critical"
        ]
        if critical_vulns:
            insights.append(
                f"🚨 CRITICAL: {len(critical_vulns)} critical vulnerabilities require immediate attention"
            )

        # Exploitability insights
        highly_exploitable = [v for v in vulnerabilities if v.exploitability > 0.8]
        if highly_exploitable:
            insights.append(
                f"⚡ {len(highly_exploitable)} vulnerabilities are highly exploitable with available tools"
            )

        # Attack vector concentration
        vector_counts = Counter(v.attack_vector for v in vulnerabilities)
        dominant_vector = vector_counts.most_common(1)[0]
        if dominant_vector[1] > len(vulnerabilities) * 0.6:
            insights.append(
                f"🎯 Attack surface concentrated in {dominant_vector[0].value} ({dominant_vector[1]} vulnerabilities)"
            )

        # Business impact insights
        high_impact_vulns = [v for v in vulnerabilities if v.business_impact >= 7.0]
        if high_impact_vulns:
            insights.append(
                f"💼 {len(high_impact_vulns)} vulnerabilities pose significant business risk"
            )

        # Remediation insights
        easy_fixes = [v for v in vulnerabilities if v.remediation_complexity <= 2]
        if easy_fixes:
            insights.append(
                f"🔧 {len(easy_fixes)} vulnerabilities can be quickly remediated with low effort"
            )

        return insights

    def _generate_contextual_recommendations(
        self, vulnerabilities: List[VulnerabilityContext], risk_context: Dict[str, Any]
    ) -> List[str]:
        """Generate contextual recommendations"""
        recommendations = []

        if not vulnerabilities:
            recommendations.extend(
                [
                    "✅ Continue regular security monitoring and assessments",
                    "🔄 Maintain current security controls and configurations",
                    "📊 Schedule next assessment in 30-60 days",
                ]
            )
            return recommendations

        # Immediate actions for critical vulnerabilities
        critical_vulns = [
            v for v in vulnerabilities if v.severity.lower() == "critical"
        ]
        if critical_vulns:
            recommendations.append(
                "🚨 IMMEDIATE: Address all critical vulnerabilities within 24 hours"
            )
            recommendations.append(
                "🔒 Consider blocking affected services until patched"
            )

        # High-priority remediation
        high_vulns = [v for v in vulnerabilities if v.severity.lower() == "high"]
        if high_vulns:
            recommendations.append(
                "🔴 HIGH PRIORITY: Remediate high-severity vulnerabilities within 48-72 hours"
            )

        # Attack vector specific recommendations
        vector_counts = Counter(v.attack_vector for v in vulnerabilities)

        if AttackVector.WEB_APPLICATION in vector_counts:
            recommendations.append(
                "🌐 Implement Web Application Firewall (WAF) for immediate protection"
            )
            recommendations.append(
                "🔍 Conduct thorough code review and implement secure coding practices"
            )

        if AttackVector.NETWORK in vector_counts:
            recommendations.append("🛡️ Review network segmentation and firewall rules")
            recommendations.append(
                "🔐 Implement network access controls and monitoring"
            )

        if AttackVector.CONFIGURATION in vector_counts:
            recommendations.append("⚙️ Conduct configuration hardening review")
            recommendations.append(
                "📋 Implement configuration management and compliance monitoring"
            )

        # Business context recommendations
        if risk_context["business_impact"] > 60:
            recommendations.append(
                "💼 Engage business stakeholders for risk acceptance decisions"
            )
            recommendations.append(
                "📊 Consider cyber insurance review given high business impact"
            )

        # Compliance recommendations
        if self.business_context.compliance_requirements:
            recommendations.append(
                f"📜 Review remediation plan against {', '.join(self.business_context.compliance_requirements)} requirements"
            )

        # Long-term strategic recommendations
        recommendations.extend(
            [
                "🔄 Implement continuous security monitoring",
                "👥 Provide security awareness training",
                "📈 Establish security metrics and KPIs",
                "🏗️ Integrate security into development lifecycle",
            ]
        )

        return recommendations


class VulnerabilityCorrelationEngine:
    """Advanced vulnerability correlation and relationship analysis"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.correlation_rules = self._initialize_correlation_rules()

    def _initialize_correlation_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize vulnerability correlation rules"""
        return {
            "attack_chains": [
                {
                    "name": "Web Application RCE Chain",
                    "pattern": ["upload", "lfi", "rce"],
                    "description": "File upload leading to local file inclusion and remote code execution",
                },
                {
                    "name": "Authentication Bypass Chain",
                    "pattern": ["auth-bypass", "privilege", "admin"],
                    "description": "Authentication bypass leading to privilege escalation",
                },
                {
                    "name": "SQL Injection Chain",
                    "pattern": ["sqli", "dump", "privilege"],
                    "description": "SQL injection leading to database compromise",
                },
            ],
            "amplification_patterns": [
                {
                    "primary": "xss",
                    "amplifiers": ["csrf", "clickjacking"],
                    "description": "XSS amplified by CSRF and clickjacking vulnerabilities",
                },
                {
                    "primary": "ssrf",
                    "amplifiers": ["cloud-metadata", "internal-service"],
                    "description": "SSRF amplified by cloud metadata access",
                },
            ],
        }

    def analyze_correlations(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> Dict[str, Any]:
        """Analyze correlations between vulnerabilities"""
        correlations = {
            "attack_chains": self._find_attack_chains(vulnerabilities),
            "vulnerability_clusters": self._cluster_vulnerabilities(vulnerabilities),
            "amplification_scenarios": self._find_amplification_scenarios(
                vulnerabilities
            ),
            "dependency_graph": self._build_dependency_graph(vulnerabilities),
            "risk_amplification_factor": self._calculate_risk_amplification(
                vulnerabilities
            ),
        }

        return correlations

    def _find_attack_chains(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Find potential attack chains"""
        chains = []

        # Group by target
        target_groups = defaultdict(list)
        for vuln in vulnerabilities:
            target_groups[vuln.target].append(vuln)

        for target, vulns in target_groups.items():
            for rule in self.correlation_rules["attack_chains"]:
                chain_vulns = self._match_chain_pattern(vulns, rule["pattern"])
                if len(chain_vulns) >= 2:  # Need at least 2 vulnerabilities for a chain
                    chains.append(
                        {
                            "name": rule["name"],
                            "target": target,
                            "vulnerabilities": [v.template_id for v in chain_vulns],
                            "risk_multiplier": len(chain_vulns) * 1.5,
                            "description": rule["description"],
                            "exploitability": max(
                                v.exploitability for v in chain_vulns
                            ),
                        }
                    )

        return sorted(chains, key=lambda c: c["risk_multiplier"], reverse=True)

    def _match_chain_pattern(
        self, vulnerabilities: List[VulnerabilityContext], pattern: List[str]
    ) -> List[VulnerabilityContext]:
        """Match vulnerabilities against a chain pattern"""
        matched = []

        for pattern_item in pattern:
            for vuln in vulnerabilities:
                if pattern_item in vuln.template_id.lower() and vuln not in matched:
                    matched.append(vuln)
                    break

        return matched

    def _cluster_vulnerabilities(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Cluster related vulnerabilities"""
        clusters = []
        processed = set()

        for vuln in vulnerabilities:
            if vuln.id in processed:
                continue

            cluster = {
                "primary_vulnerability": vuln.template_id,
                "target": vuln.target,
                "members": [vuln],
                "cluster_type": self._determine_cluster_type(vuln),
                "combined_risk": vuln.business_impact,
            }

            # Find related vulnerabilities
            for other_vuln in vulnerabilities:
                if other_vuln.id != vuln.id and other_vuln.id not in processed:
                    if self._are_vulnerabilities_clustered(vuln, other_vuln):
                        cluster["members"].append(other_vuln)
                        cluster["combined_risk"] += (
                            other_vuln.business_impact * 0.5
                        )  # Diminishing returns
                        processed.add(other_vuln.id)

            if len(cluster["members"]) > 1:  # Only include multi-member clusters
                cluster["member_count"] = len(cluster["members"])
                cluster["member_templates"] = [
                    v.template_id for v in cluster["members"]
                ]
                clusters.append(cluster)

            processed.add(vuln.id)

        return sorted(clusters, key=lambda c: c["combined_risk"], reverse=True)

    def _determine_cluster_type(self, vuln: VulnerabilityContext) -> str:
        """Determine the type of vulnerability cluster"""
        template_lower = vuln.template_id.lower()

        if any(pattern in template_lower for pattern in ["sqli", "sql"]):
            return "SQL_INJECTION_CLUSTER"
        elif any(pattern in template_lower for pattern in ["xss", "cross-site"]):
            return "XSS_CLUSTER"
        elif any(pattern in template_lower for pattern in ["auth", "session"]):
            return "AUTHENTICATION_CLUSTER"
        elif any(pattern in template_lower for pattern in ["config", "default"]):
            return "CONFIGURATION_CLUSTER"
        elif any(pattern in template_lower for pattern in ["ssl", "tls", "crypto"]):
            return "CRYPTOGRAPHIC_CLUSTER"
        else:
            return "GENERAL_CLUSTER"

    def _are_vulnerabilities_clustered(
        self, vuln1: VulnerabilityContext, vuln2: VulnerabilityContext
    ) -> bool:
        """Check if two vulnerabilities should be clustered"""
        # Same target and attack vector
        if vuln1.target == vuln2.target and vuln1.attack_vector == vuln2.attack_vector:
            return True

        # Similar template patterns
        template1_base = re.sub(r"-\d+$", "", vuln1.template_id.lower())
        template2_base = re.sub(r"-\d+$", "", vuln2.template_id.lower())

        if template1_base == template2_base:
            return True

        # Related vulnerability types
        related_patterns = [
            ["sqli", "sql-injection"],
            ["xss", "cross-site-scripting"],
            ["rce", "code-execution"],
            ["lfi", "file-inclusion"],
            ["auth", "authentication", "session"],
        ]

        for pattern_group in related_patterns:
            if any(p in vuln1.template_id.lower() for p in pattern_group) and any(
                p in vuln2.template_id.lower() for p in pattern_group
            ):
                return True

        return False

    def _find_amplification_scenarios(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Find vulnerability amplification scenarios"""
        scenarios = []

        for rule in self.correlation_rules["amplification_patterns"]:
            primary_vulns = [
                v for v in vulnerabilities if rule["primary"] in v.template_id.lower()
            ]

            for primary in primary_vulns:
                amplifiers = []
                for amplifier_pattern in rule["amplifiers"]:
                    for vuln in vulnerabilities:
                        if (
                            amplifier_pattern in vuln.template_id.lower()
                            and vuln.target == primary.target
                            and vuln.id != primary.id
                        ):
                            amplifiers.append(vuln)

                if amplifiers:
                    amplification_factor = 1.0 + (len(amplifiers) * 0.3)
                    scenarios.append(
                        {
                            "primary_vulnerability": primary.template_id,
                            "target": primary.target,
                            "amplifiers": [a.template_id for a in amplifiers],
                            "amplification_factor": amplification_factor,
                            "description": rule["description"],
                            "combined_exploitability": min(
                                primary.exploitability * amplification_factor, 1.0
                            ),
                        }
                    )

        return scenarios

    def _build_dependency_graph(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> Dict[str, Any]:
        """Build vulnerability dependency graph"""
        graph = {"nodes": [], "edges": [], "critical_paths": []}

        # Create nodes
        for vuln in vulnerabilities:
            graph["nodes"].append(
                {
                    "id": vuln.id,
                    "template_id": vuln.template_id,
                    "target": vuln.target,
                    "severity": vuln.severity,
                    "exploitability": vuln.exploitability,
                    "business_impact": vuln.business_impact,
                }
            )

        # Create edges based on relationships
        for i, vuln1 in enumerate(vulnerabilities):
            for j, vuln2 in enumerate(vulnerabilities):
                if i != j:
                    relationship = self._determine_relationship(vuln1, vuln2)
                    if relationship:
                        graph["edges"].append(
                            {
                                "source": vuln1.id,
                                "target": vuln2.id,
                                "relationship": relationship,
                                "weight": self._calculate_relationship_weight(
                                    vuln1, vuln2, relationship
                                ),
                            }
                        )

        # Find critical paths (simplified)
        graph["critical_paths"] = self._find_critical_paths(vulnerabilities)

        return graph

    def _determine_relationship(
        self, vuln1: VulnerabilityContext, vuln2: VulnerabilityContext
    ) -> Optional[str]:
        """Determine relationship between two vulnerabilities"""
        # Prerequisites (one enables the other)
        prerequisite_patterns = [
            (["auth-bypass"], ["privilege", "admin"]),
            (["upload"], ["rce", "lfi"]),
            (["sqli"], ["dump", "privilege"]),
            (["xss"], ["csrf", "session"]),
        ]

        for prereq, enabled in prerequisite_patterns:
            if any(p in vuln1.template_id.lower() for p in prereq) and any(
                e in vuln2.template_id.lower() for e in enabled
            ):
                return "ENABLES"

        # Amplification (one makes the other worse)
        if vuln1.target == vuln2.target and vuln1.attack_vector == vuln2.attack_vector:
            return "AMPLIFIES"

        return None

    def _calculate_relationship_weight(
        self,
        vuln1: VulnerabilityContext,
        vuln2: VulnerabilityContext,
        relationship: str,
    ) -> float:
        """Calculate weight of relationship between vulnerabilities"""
        if relationship == "ENABLES":
            return vuln2.business_impact * vuln1.exploitability
        elif relationship == "AMPLIFIES":
            return (vuln1.business_impact + vuln2.business_impact) * 0.5

        return 1.0

    def _find_critical_paths(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> List[Dict[str, Any]]:
        """Find critical attack paths through the vulnerability graph"""
        paths = []

        # Group by target
        target_groups = defaultdict(list)
        for vuln in vulnerabilities:
            target_groups[vuln.target].append(vuln)

        for target, vulns in target_groups.items():
            # Sort by attack chain position
            sorted_vulns = sorted(vulns, key=lambda v: v.attack_chain_position)

            if len(sorted_vulns) >= 2:
                path_risk = sum(
                    v.business_impact * v.exploitability for v in sorted_vulns[:3]
                )  # Top 3
                paths.append(
                    {
                        "target": target,
                        "path": [v.template_id for v in sorted_vulns[:3]],
                        "path_risk": path_risk,
                        "estimated_time": self._estimate_path_time(sorted_vulns[:3]),
                    }
                )

        return sorted(paths, key=lambda p: p["path_risk"], reverse=True)[:5]

    def _estimate_path_time(self, vulnerabilities: List[VulnerabilityContext]) -> str:
        """Estimate time to complete attack path"""
        total_complexity = sum(v.remediation_complexity for v in vulnerabilities)
        avg_exploitability = statistics.mean(
            [v.exploitability for v in vulnerabilities]
        )

        if avg_exploitability > 0.8 and total_complexity <= 6:
            return "Hours"
        elif avg_exploitability > 0.6 and total_complexity <= 10:
            return "Days"
        else:
            return "Weeks"

    def _calculate_risk_amplification(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> float:
        """Calculate overall risk amplification factor"""
        if len(vulnerabilities) <= 1:
            return 1.0

        # Base amplification from vulnerability count
        count_factor = 1.0 + (len(vulnerabilities) - 1) * 0.1

        # Amplification from attack chains
        chain_count = len(self._find_attack_chains(vulnerabilities))
        chain_factor = 1.0 + (chain_count * 0.2)

        # Amplification from clusters
        cluster_count = len(self._cluster_vulnerabilities(vulnerabilities))
        cluster_factor = 1.0 + (cluster_count * 0.15)

        total_amplification = count_factor * chain_factor * cluster_factor

        return min(total_amplification, 3.0)  # Cap at 3x amplification


class ThreatIntelligenceAggregator:
    """Aggregate and correlate threat intelligence data"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.intelligence_cache = {}
        self.threat_feeds = self._initialize_threat_feeds()

    def _initialize_threat_feeds(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat intelligence feeds configuration"""
        return {
            "abuse_ch": {
                "url_patterns": ["malware-bazaar", "threatfox", "urlhaus"],
                "confidence_weight": 0.9,
            },
            "virustotal": {
                "api_endpoint": "virustotal.com/api/v3",
                "confidence_weight": 0.8,
            },
            "shodan": {"api_endpoint": "api.shodan.io", "confidence_weight": 0.7},
            "otx": {"api_endpoint": "otx.alienvault.com", "confidence_weight": 0.6},
        }

    def aggregate_threat_intelligence(
        self, vulnerabilities: List[VulnerabilityContext], targets: List[str]
    ) -> ThreatIntelligence:
        """Aggregate threat intelligence for vulnerabilities and targets"""
        # Initialize intelligence structure
        intelligence = ThreatIntelligence(
            reputation_score=100.0,
            known_malicious_ips=[],
            suspicious_domains=[],
            threat_feeds={},
            geolocation_risks={},
            dark_web_mentions=0,
            recent_campaigns=[],
        )

        # Analyze each target
        for target in targets:
            target_intel = self._analyze_target_intelligence(target)
            self._merge_intelligence(intelligence, target_intel)

        # Analyze vulnerability patterns
        vuln_intel = self._analyze_vulnerability_intelligence(vulnerabilities)
        self._merge_intelligence(intelligence, vuln_intel)

        # Calculate overall reputation score
        intelligence.reputation_score = self._calculate_reputation_score(intelligence)

        return intelligence

    def _analyze_target_intelligence(self, target: str) -> Dict[str, Any]:
        """Analyze threat intelligence for a specific target"""
        intel = {
            "reputation_score": 100.0,
            "malicious_indicators": [],
            "suspicious_indicators": [],
            "geolocation_risk": 0.0,
            "threat_feed_matches": {},
        }

        try:
            # Extract domain/IP from target
            from urllib.parse import urlparse

            parsed = urlparse(
                target if target.startswith("http") else f"http://{target}"
            )
            domain = parsed.netloc or target

            # Check cached intelligence
            cache_key = f"target_{domain}"
            if cache_key in self.intelligence_cache:
                cached_time = self.intelligence_cache[cache_key].get("timestamp", 0)
                if datetime.now().timestamp() - cached_time < 3600:  # 1 hour cache
                    return self.intelligence_cache[cache_key]["data"]

            # Simulate threat intelligence checks (in production, call real APIs)
            intel = self._simulate_threat_intelligence_lookup(domain)

            # Cache the result
            self.intelligence_cache[cache_key] = {
                "data": intel,
                "timestamp": datetime.now().timestamp(),
            }

        except Exception as e:
            self.logger.warning(
                f"Failed to analyze threat intelligence for {target}: {e}"
            )

        return intel

    def _simulate_threat_intelligence_lookup(self, domain: str) -> Dict[str, Any]:
        """Simulate threat intelligence lookup (replace with real API calls)"""
        intel = {
            "reputation_score": 100.0,
            "malicious_indicators": [],
            "suspicious_indicators": [],
            "geolocation_risk": 0.0,
            "threat_feed_matches": {},
        }

        # Simulate some intelligence based on domain characteristics
        domain_lower = domain.lower()

        # Check for suspicious patterns
        suspicious_patterns = [
            "bit.ly",
            "tinyurl",
            "temp",
            "test",
            "dev",
            "staging",
            "admin",
            "login",
            "secure",
            "bank",
            "paypal",
        ]

        for pattern in suspicious_patterns:
            if pattern in domain_lower:
                intel["suspicious_indicators"].append(
                    f"Contains suspicious pattern: {pattern}"
                )
                intel["reputation_score"] -= 5.0

        # Simulate geolocation risk
        high_risk_tlds = [".ru", ".cn", ".tk", ".ml", ".ga"]
        for tld in high_risk_tlds:
            if domain_lower.endswith(tld):
                intel["geolocation_risk"] = 7.0
                intel["reputation_score"] -= 10.0
                break

        # Simulate threat feed matches
        if len(domain) > 20 or any(char.isdigit() for char in domain.replace(".", "")):
            intel["threat_feed_matches"]["suspicious_domain_patterns"] = True
            intel["reputation_score"] -= 3.0

        return intel

    def _analyze_vulnerability_intelligence(
        self, vulnerabilities: List[VulnerabilityContext]
    ) -> Dict[str, Any]:
        """Analyze threat intelligence based on vulnerability patterns"""
        intel = {
            "reputation_score": 0.0,
            "malicious_indicators": [],
            "suspicious_indicators": [],
            "campaign_matches": [],
            "exploit_intelligence": {},
        }

        # Analyze vulnerability patterns for known campaigns
        vuln_templates = [v.template_id for v in vulnerabilities]

        # Check for known campaign patterns
        campaign_patterns = {
            "mass_scanning_campaign": ["nuclei", "scanner", "automated"],
            "targeted_attack": ["custom", "specific", "manual"],
            "opportunistic_attack": ["common", "widespread", "default"],
        }

        for campaign, patterns in campaign_patterns.items():
            matches = sum(
                1
                for template in vuln_templates
                for pattern in patterns
                if pattern in template.lower()
            )

            if matches > 0:
                intel["campaign_matches"].append(
                    {
                        "campaign_type": campaign,
                        "confidence": min(matches / len(vuln_templates), 1.0),
                        "matched_vulnerabilities": matches,
                    }
                )

        # Analyze exploit availability
        high_exploitability_vulns = [
            v for v in vulnerabilities if v.exploitability > 0.7
        ]
        if high_exploitability_vulns:
            intel["exploit_intelligence"]["high_risk_count"] = len(
                high_exploitability_vulns
            )
            intel["exploit_intelligence"]["public_exploits"] = sum(
                1 for v in high_exploitability_vulns if v.public_exploit_available
            )

        return intel

    def _merge_intelligence(
        self, target_intel: ThreatIntelligence, source_intel: Dict[str, Any]
    ):
        """Merge intelligence from different sources"""
        # Merge malicious indicators
        if "malicious_indicators" in source_intel:
            target_intel.known_malicious_ips.extend(
                source_intel["malicious_indicators"]
            )

        # Merge suspicious indicators
        if "suspicious_indicators" in source_intel:
            target_intel.suspicious_domains.extend(
                source_intel["suspicious_indicators"]
            )

        # Merge threat feed data
        if "threat_feed_matches" in source_intel:
            target_intel.threat_feeds.update(source_intel["threat_feed_matches"])

        # Merge geolocation risks
        if "geolocation_risk" in source_intel:
            risk_score = source_intel["geolocation_risk"]
            if risk_score > 0:
                target_intel.geolocation_risks["unknown_source"] = risk_score

        # Merge campaign matches
        if "campaign_matches" in source_intel:
            target_intel.recent_campaigns.extend(source_intel["campaign_matches"])

    def _calculate_reputation_score(self, intelligence: ThreatIntelligence) -> float:
        """Calculate overall reputation score"""
        base_score = 100.0

        # Deduct for malicious indicators
        base_score -= len(intelligence.known_malicious_ips) * 10.0

        # Deduct for suspicious indicators
        base_score -= len(intelligence.suspicious_domains) * 3.0

        # Deduct for geolocation risks
        base_score -= sum(intelligence.geolocation_risks.values()) * 2.0

        # Deduct for threat feed matches
        base_score -= len(intelligence.threat_feeds) * 5.0

        # Deduct for recent campaigns
        base_score -= len(intelligence.recent_campaigns) * 7.0

        return max(0.0, min(100.0, base_score))
