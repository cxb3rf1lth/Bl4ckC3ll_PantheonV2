#!/usr/bin/env python3
"""
Enhanced Validation and Reliability System for Bl4ckC3ll_PANTHEON
Provides comprehensive input validation, result verification, and reliability tracking
"""

import re
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import ipaddress
from urllib.parse import urlparse
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
import requests
from collections import defaultdict, Counter

@dataclass
class ValidationResult:
    """Result of input validation"""
    is_valid: bool
    cleaned_input: str
    validation_type: str
    confidence_score: float = 0.0
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

@dataclass
class ReliabilityMetrics:
    """Track reliability metrics for scanning operations"""
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    false_positives: int = 0
    verified_findings: int = 0
    avg_response_time: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        if self.total_operations == 0:
            return 0.0
        return self.successful_operations / self.total_operations
    
    @property
    def accuracy_rate(self) -> float:
        total_findings = self.false_positives + self.verified_findings
        if total_findings == 0:
            return 1.0
        return self.verified_findings / total_findings

class EnhancedValidator:
    """Enhanced input validation with security and reliability focus"""
    
    def __init__(self):
        self.domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        self.ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        self.url_pattern = re.compile(
            r'^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::[0-9]{1,5})?(?:/.*)?$'
        )
        
        # Security patterns to detect and sanitize
        self.dangerous_patterns = [
            r'[;&|`$(){}]',  # Command injection
            r'<script[^>]*>.*?</script>',  # XSS
            r'(\.\./|\.\.\\)',  # Path traversal
            r'(union|select|insert|delete|update|drop)\s+',  # SQL injection keywords
            r'javascript:',  # JavaScript protocol
            r'data:',  # Data protocol
            r'file:',  # File protocol
        ]
        
        self.compiled_dangerous_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.dangerous_patterns]
    
    def validate_domain(self, domain: str) -> ValidationResult:
        """Enhanced domain validation with security checks and DNS verification"""
        if not domain or not isinstance(domain, str):
            return ValidationResult(False, "", "domain", 0.0, ["Empty or invalid input"])
        
        # Clean and normalize
        cleaned = domain.strip().lower()
        warnings = []
        suggestions = []
        confidence = 0.0
        
        # Security checks
        for pattern in self.compiled_dangerous_patterns:
            if pattern.search(cleaned):
                return ValidationResult(False, "", "domain", 0.0, ["Potentially malicious input detected"])
        
        # Length checks
        if len(cleaned) > 253:
            return ValidationResult(False, "", "domain", 0.0, ["Domain too long (max 253 characters)"])
        
        if len(cleaned) < 1:
            return ValidationResult(False, "", "domain", 0.0, ["Domain too short"])
        
        # Pattern validation
        if not self.domain_pattern.match(cleaned):
            return ValidationResult(False, "", "domain", 0.0, ["Invalid domain format"])
        
        # DNS verification (optional - adds reliability)
        if DNS_AVAILABLE:
            try:
                dns.resolver.resolve(cleaned, 'A')
                confidence += 0.4
            except:
                warnings.append("Domain does not resolve to IP address")
                suggestions.append("Verify domain is active and properly configured")
        else:
            warnings.append("DNS verification unavailable")
            suggestions.append("Install dnspython for enhanced domain validation")
        
        # Additional checks
        if cleaned.count('.') == 0:
            warnings.append("No subdomain detected - might be incomplete")
            confidence -= 0.1
        else:
            confidence += 0.2
        
        # Check for suspicious characteristics
        if len(cleaned) > 50:
            warnings.append("Unusually long domain name")
        
        if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', cleaned):
            suggestions.append("Domain appears to be IP-based - consider using IP validation")
        
        confidence = max(0.0, min(1.0, confidence + 0.4))  # Base confidence
        
        return ValidationResult(True, cleaned, "domain", confidence, warnings, suggestions)
    
    def validate_ip(self, ip: str) -> ValidationResult:
        """Enhanced IP validation with range and security checks"""
        if not ip or not isinstance(ip, str):
            return ValidationResult(False, "", "ip", 0.0, ["Empty or invalid input"])
        
        cleaned = ip.strip()
        warnings = []
        suggestions = []
        confidence = 0.8  # Base confidence for valid IPs
        
        # Security checks
        for pattern in self.compiled_dangerous_patterns:
            if pattern.search(cleaned):
                return ValidationResult(False, "", "ip", 0.0, ["Potentially malicious input detected"])
        
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            
            # Check for private/special ranges
            if ip_obj.is_private:
                warnings.append("Private IP address - may not be accessible externally")
                confidence -= 0.2
            
            if ip_obj.is_loopback:
                warnings.append("Loopback address detected")
                suggestions.append("Consider using external IP for security testing")
                confidence -= 0.3
            
            if ip_obj.is_reserved:
                warnings.append("Reserved IP address")
                confidence -= 0.2
            
            if ip_obj.is_multicast:
                return ValidationResult(False, "", "ip", 0.0, ["Multicast addresses not supported"])
            
            # Version-specific checks
            if isinstance(ip_obj, ipaddress.IPv6Address):
                suggestions.append("IPv6 address - ensure tools support IPv6")
                confidence -= 0.1
            
            return ValidationResult(True, cleaned, "ip", confidence, warnings, suggestions)
        
        except ValueError:
            return ValidationResult(False, "", "ip", 0.0, ["Invalid IP address format"])
    
    def validate_url(self, url: str) -> ValidationResult:
        """Enhanced URL validation with security and accessibility checks"""
        if not url or not isinstance(url, str):
            return ValidationResult(False, "", "url", 0.0, ["Empty or invalid input"])
        
        cleaned = url.strip()
        warnings = []
        suggestions = []
        confidence = 0.6  # Base confidence
        
        # Security checks
        for pattern in self.compiled_dangerous_patterns:
            if pattern.search(cleaned):
                return ValidationResult(False, "", "url", 0.0, ["Potentially malicious input detected"])
        
        # Add protocol if missing
        if not cleaned.startswith(('http://', 'https://')):
            cleaned = 'https://' + cleaned
            suggestions.append("Added HTTPS protocol - consider verifying correct protocol")
        
        try:
            parsed = urlparse(cleaned)
            
            # Validate components
            if not parsed.netloc:
                return ValidationResult(False, "", "url", 0.0, ["Missing hostname in URL"])
            
            # Security checks
            if parsed.scheme not in ['http', 'https']:
                return ValidationResult(False, "", "url", 0.0, ["Only HTTP/HTTPS protocols supported"])
            
            if parsed.scheme == 'http':
                warnings.append("Using HTTP (unencrypted) - consider HTTPS")
                confidence -= 0.1
            else:
                confidence += 0.1
            
            # Port validation
            if parsed.port:
                if parsed.port < 1 or parsed.port > 65535:
                    return ValidationResult(False, "", "url", 0.0, ["Invalid port number"])
                if parsed.port not in [80, 443, 8080, 8443]:
                    warnings.append(f"Non-standard port {parsed.port} detected")
            
            # Domain validation
            domain_result = self.validate_domain(parsed.netloc.split(':')[0])
            if not domain_result.is_valid:
                return ValidationResult(False, "", "url", 0.0, ["Invalid domain in URL"])
            
            confidence += domain_result.confidence_score * 0.3
            warnings.extend(domain_result.warnings)
            
            # Accessibility check (optional)
            try:
                response = requests.head(cleaned, timeout=10, allow_redirects=True)
                if response.status_code < 400:
                    confidence += 0.2
                else:
                    warnings.append(f"URL returned status code {response.status_code}")
            except:
                warnings.append("URL accessibility could not be verified")
            
            return ValidationResult(True, cleaned, "url", confidence, warnings, suggestions)
        
        except Exception as e:
            return ValidationResult(False, "", "url", 0.0, [f"URL parsing error: {str(e)}"])
    
    def validate_input_list(self, inputs: List[str], input_type: str = "auto") -> List[ValidationResult]:
        """Validate a list of inputs with type auto-detection"""
        results = []
        
        for inp in inputs:
            if input_type == "auto":
                # Auto-detect input type
                if self.ip_pattern.match(inp.strip()):
                    result = self.validate_ip(inp)
                elif inp.strip().startswith(('http://', 'https://')):
                    result = self.validate_url(inp)
                else:
                    result = self.validate_domain(inp)
            elif input_type == "domain":
                result = self.validate_domain(inp)
            elif input_type == "ip":
                result = self.validate_ip(inp)
            elif input_type == "url":
                result = self.validate_url(inp)
            else:
                result = ValidationResult(False, "", "unknown", 0.0, ["Unknown input type"])
            
            results.append(result)
        
        return results
    
    def bulk_validate_and_clean(self, inputs: List[str]) -> Tuple[List[str], List[str], Dict[str, Any]]:
        """Bulk validate inputs and return cleaned valid inputs, invalid inputs, and stats"""
        results = self.validate_input_list(inputs)
        
        valid_inputs = []
        invalid_inputs = []
        stats = {
            'total': len(inputs),
            'valid': 0,
            'invalid': 0,
            'avg_confidence': 0.0,
            'warnings_count': 0,
            'types_detected': Counter()
        }
        
        total_confidence = 0.0
        
        for inp, result in zip(inputs, results):
            if result.is_valid:
                valid_inputs.append(result.cleaned_input)
                stats['valid'] += 1
                total_confidence += result.confidence_score
                stats['types_detected'][result.validation_type] += 1
            else:
                invalid_inputs.append(inp)
                stats['invalid'] += 1
            
            stats['warnings_count'] += len(result.warnings)
        
        if stats['valid'] > 0:
            stats['avg_confidence'] = total_confidence / stats['valid']
        
        return valid_inputs, invalid_inputs, stats

class ReliabilityTracker:
    """Track and improve system reliability"""
    
    def __init__(self):
        self.metrics: Dict[str, ReliabilityMetrics] = defaultdict(ReliabilityMetrics)
        self.verification_cache: Dict[str, Dict] = {}
        self.false_positive_patterns: Set[str] = set()
    
    def record_operation(self, operation_type: str, success: bool, response_time: float = 0.0):
        """Record the result of an operation"""
        metrics = self.metrics[operation_type]
        metrics.total_operations += 1
        
        if success:
            metrics.successful_operations += 1
        else:
            metrics.failed_operations += 1
        
        # Update average response time
        if response_time > 0:
            current_avg = metrics.avg_response_time
            total_ops = metrics.total_operations
            metrics.avg_response_time = ((current_avg * (total_ops - 1)) + response_time) / total_ops
        
        metrics.last_updated = datetime.now()
    
    def record_finding_verification(self, operation_type: str, finding_hash: str, is_verified: bool):
        """Record whether a finding was verified as true positive or false positive"""
        metrics = self.metrics[operation_type]
        
        if is_verified:
            metrics.verified_findings += 1
        else:
            metrics.false_positives += 1
            # Add to false positive patterns for learning
            self.false_positive_patterns.add(finding_hash[:8])  # Store partial hash
    
    def is_likely_false_positive(self, finding_data: str) -> bool:
        """Check if a finding is likely a false positive based on patterns"""
        finding_hash = hashlib.md5(finding_data.encode()).hexdigest()
        return finding_hash[:8] in self.false_positive_patterns
    
    def get_reliability_score(self, operation_type: str) -> float:
        """Get overall reliability score for an operation type"""
        metrics = self.metrics.get(operation_type)
        if not metrics or metrics.total_operations == 0:
            return 0.0
        
        # Weighted score combining success rate and accuracy
        success_weight = 0.6
        accuracy_weight = 0.4
        
        return (metrics.success_rate * success_weight) + (metrics.accuracy_rate * accuracy_weight)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        summary = {
            'overall_reliability': 0.0,
            'operations': {},
            'recommendations': []
        }
        
        total_reliability = 0.0
        operation_count = 0
        
        for op_type, metrics in self.metrics.items():
            reliability = self.get_reliability_score(op_type)
            total_reliability += reliability
            operation_count += 1
            
            summary['operations'][op_type] = {
                'success_rate': metrics.success_rate,
                'accuracy_rate': metrics.accuracy_rate,
                'reliability_score': reliability,
                'total_operations': metrics.total_operations,
                'avg_response_time': metrics.avg_response_time
            }
            
            # Generate recommendations
            if metrics.success_rate < 0.8:
                summary['recommendations'].append(f"Improve {op_type} success rate (currently {metrics.success_rate:.1%})")
            
            if metrics.accuracy_rate < 0.9:
                summary['recommendations'].append(f"Reduce {op_type} false positives (accuracy: {metrics.accuracy_rate:.1%})")
        
        if operation_count > 0:
            summary['overall_reliability'] = total_reliability / operation_count
        
        return summary
    
    def export_metrics(self, file_path: str):
        """Export reliability metrics to file"""
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': self.get_performance_summary(),
            'detailed_metrics': {}
        }
        
        for op_type, metrics in self.metrics.items():
            export_data['detailed_metrics'][op_type] = {
                'total_operations': metrics.total_operations,
                'successful_operations': metrics.successful_operations,
                'failed_operations': metrics.failed_operations,
                'false_positives': metrics.false_positives,
                'verified_findings': metrics.verified_findings,
                'avg_response_time': metrics.avg_response_time,
                'success_rate': metrics.success_rate,
                'accuracy_rate': metrics.accuracy_rate,
                'last_updated': metrics.last_updated.isoformat()
            }
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)

# Global instances
enhanced_validator = EnhancedValidator()
reliability_tracker = ReliabilityTracker()

def validate_target_input(target: str, input_type: str = "auto") -> ValidationResult:
    """Validate a single target input"""
    if input_type == "auto":
        # Auto-detect type
        if enhanced_validator.ip_pattern.match(target.strip()):
            return enhanced_validator.validate_ip(target)
        elif target.strip().startswith(('http://', 'https://')):
            return enhanced_validator.validate_url(target)
        else:
            return enhanced_validator.validate_domain(target)
    elif input_type == "domain":
        return enhanced_validator.validate_domain(target)
    elif input_type == "ip":
        return enhanced_validator.validate_ip(target)
    elif input_type == "url":
        return enhanced_validator.validate_url(target)
    else:
        return ValidationResult(False, "", "unknown", 0.0, ["Unknown input type"])

def validate_targets_file(file_path: str) -> Tuple[List[str], Dict[str, Any]]:
    """Validate targets from a file and return cleaned targets with stats"""
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        valid_targets, invalid_targets, stats = enhanced_validator.bulk_validate_and_clean(lines)
        
        stats['file_path'] = file_path
        stats['total_lines'] = len(lines)
        
        return valid_targets, stats
    
    except Exception as e:
        return [], {'error': str(e), 'file_path': file_path}

def get_system_reliability_score() -> float:
    """Get overall system reliability score"""
    summary = reliability_tracker.get_performance_summary()
    return summary.get('overall_reliability', 0.0)

if __name__ == "__main__":
    # Test the validation system
    print("Enhanced Validation System - Test")
    
    test_inputs = [
        "example.com",
        "192.168.1.1",
        "https://example.com",
        "invalid..domain",
        "127.0.0.1",
        "javascript:alert(1)"
    ]
    
    for inp in test_inputs:
        result = validate_target_input(inp)
        status = "✅" if result.is_valid else "❌"
        print(f"{status} {inp} -> {result.cleaned_input} (confidence: {result.confidence_score:.1%})")
        
        if result.warnings:
            for warning in result.warnings:
                print(f"  ⚠️  {warning}")
        
        if result.suggestions:
            for suggestion in result.suggestions:
                print(f"  💡 {suggestion}")