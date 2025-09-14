#!/usr/bin/env python3
"""
Enhanced Scanner Module - Alias for enhanced_scanning
This module provides a consistent import interface for the enhanced scanning functionality.
"""

# Import all public components from enhanced_scanning
from enhanced_scanning import (
    AdaptiveScanManager,
    EnhancedScanner,
    PerformanceMetrics,
    ScanResult,
    get_current_success_rate,
    get_performance_report,
    run_enhanced_scanning,
)

# Make them available for direct import
__all__ = [
    "AdaptiveScanManager",
    "EnhancedScanner",
    "ScanResult",
    "PerformanceMetrics",
    "get_current_success_rate",
    "get_performance_report",
    "run_enhanced_scanning",
]

# Module metadata
__version__ = "2.0.0"
__author__ = "Bl4ckC3ll_PANTHEON Team"
__description__ = (
    "Enhanced scanning capabilities with adaptive performance optimization"
)
