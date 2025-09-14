"""
Bl4ckC3ll_PANTHEON Security Testing Framework
Advanced security testing orchestrator with reconnaissance, vulnerability scanning, and reporting.

Author: @cxb3rf1lth
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "@cxb3rf1lth"
__description__ = "Advanced Security Testing Framework"

# Core framework modules
try:
    from .core import SecurityManager, CommandValidator, PantheonLogger, ConfigManager
except ImportError:
    # Fallback for basic functionality
    SecurityManager = None
    CommandValidator = None  
    PantheonLogger = None
    ConfigManager = None

# Main functional modules  
from . import reporting
from . import cloud
from . import api
from . import containers
from . import cicd

# Initialize empty modules for compatibility
try:
    from . import recon
except ImportError:
    recon = None

try:
    from . import scanning  
except ImportError:
    scanning = None

try:
    from . import plugins
except ImportError:
    plugins = None

# Core exports
__all__ = [
    'SecurityManager', 'CommandValidator', 'PantheonLogger', 'ConfigManager',
    'reporting', 'cloud', 'api', 'containers', 'cicd'
]