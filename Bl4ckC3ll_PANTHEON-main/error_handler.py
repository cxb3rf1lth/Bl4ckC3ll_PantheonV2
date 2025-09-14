#!/usr/bin/env python3
"""
Enhanced error handling and logging utilities for Bl4ckC3ll_PANTHEON
Provides structured error handling, logging, and recovery mechanisms
"""

import sys
import traceback
import functools
import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TypeVar, Union
from datetime import datetime
import json

# Type variable for decorated functions
F = TypeVar('F', bound=Callable[..., Any])


class SecurityTestingError(Exception):
    """Base exception for security testing operations"""
    pass


class ConfigurationError(SecurityTestingError):
    """Configuration-related errors"""
    pass


class ToolExecutionError(SecurityTestingError):
    """External tool execution errors"""
    def __init__(self, tool_name: str, message: str, return_code: Optional[int] = None):
        self.tool_name = tool_name
        self.return_code = return_code
        super().__init__(f"{tool_name}: {message}")


class NetworkError(SecurityTestingError):
    """Network-related errors"""
    pass


class ValidationError(SecurityTestingError):
    """Input validation errors"""
    pass


class EnhancedLogger:
    """Enhanced logger with structured logging and error context"""
    
    def __init__(self, name: str = "bl4ckc3ll_pantheon", log_dir: Path = None):
        self.name = name
        self.log_dir = log_dir or Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Set up logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler
        log_file = self.log_dir / f"{name}.log"
        self.log_file = log_file
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler  
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        simple_formatter = logging.Formatter('%(levelname)s: %(message)s')
        
        file_handler.setFormatter(detailed_formatter)
        console_handler.setFormatter(simple_formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Error context tracking
        self.error_context: Dict[str, Any] = {}
    
    def set_context(self, **kwargs) -> None:
        """Set context information for error reporting"""
        self.error_context.update(kwargs)
    
    def clear_context(self) -> None:
        """Clear error context"""
        self.error_context.clear()
    
    def log(self, message: str, level: str = "INFO", **kwargs) -> None:
        """Enhanced logging with context"""
        # Combine context with additional kwargs
        context = {**self.error_context, **kwargs}
        
        if context:
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            message = f"{message} [{context_str}]"
        
        level_map = {
            "DEBUG": self.logger.debug,
            "INFO": self.logger.info,
            "WARNING": self.logger.warning,
            "ERROR": self.logger.error,
            "CRITICAL": self.logger.critical
        }
        
        log_func = level_map.get(level.upper(), self.logger.info)
        log_func(message)
    
    def log_exception(self, exc: Exception, message: str = "Exception occurred") -> None:
        """Log exception with full context and traceback"""
        self.logger.error(
            f"{message}: {exc}",
            exc_info=True,
            extra={"context": self.error_context}
        )
    
    def log_tool_error(self, tool_name: str, error: str, return_code: Optional[int] = None) -> None:
        """Log tool execution errors with structured information"""
        error_info = {
            "tool": tool_name,
            "error": error,
            "return_code": return_code,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.log(
            f"Tool execution failed: {tool_name}",
            "ERROR",
            **error_info
        )
    
    def export_error_summary(self) -> Dict[str, Any]:
        """Export error summary for reporting"""
        summary = {
            "total_errors": self._count_log_entries("ERROR"),
            "total_warnings": self._count_log_entries("WARNING"),
            "total_critical": self._count_log_entries("CRITICAL"),
            "log_file": str(self.log_file) if hasattr(self, 'log_file') else None,
            "generated_at": datetime.utcnow().isoformat()
        }
        return summary
    
    def _count_log_entries(self, level: str) -> int:
        """Count log entries of specific level"""
        if not hasattr(self, 'log_file') or not self.log_file.exists():
            return 0
        
        try:
            with open(self.log_file, 'r') as f:
                return sum(1 for line in f if f" - {level} - " in line)
        except Exception:
            return 0

    # Backward compatibility methods
    def log_with_context(self, level: str, message: str, context: Dict[str, Any] = None):
        """Log message with additional context information - backward compatibility"""
        if context:
            self.set_context(**context)
        self.log(message, level.upper())
        if context:
            self.clear_context()
    
    def error(self, message: str, context: Dict[str, Any] = None, exc_info: bool = True):
        """Log error with full context and exception information"""
        if context:
            self.set_context(**context)
        if exc_info and sys.exc_info()[0]:
            self.log_exception(sys.exc_info()[1], message)
        else:
            self.log(message, "ERROR")
        if context:
            self.clear_context()
    
    def warning(self, message: str, context: Dict[str, Any] = None):
        """Log warning with context"""
        self.log_with_context('warning', message, context)
    
    def info(self, message: str, context: Dict[str, Any] = None):
        """Log info with context"""
        self.log_with_context('info', message, context)
    
    def debug(self, message: str, context: Dict[str, Any] = None):
        """Log debug with context"""
        self.log_with_context('debug', message, context)


class ErrorRecoveryManager:
    """Manages error recovery and retry strategies"""
    
    def __init__(self, logger: EnhancedLogger):
        self.logger = logger
        self.failure_counts = {}
    
    def retry_with_exponential_backoff(
        self, 
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exceptions: tuple = (Exception,)
    ):
        """Decorator for retrying functions with exponential backoff"""
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                
                for attempt in range(max_retries + 1):
                    try:
                        result = func(*args, **kwargs)
                        
                        # Reset failure count on success
                        func_name = f"{func.__module__}.{func.__name__}"
                        if func_name in self.failure_counts:
                            del self.failure_counts[func_name]
                        
                        return result
                        
                    except exceptions as e:
                        last_exception = e
                        func_name = f"{func.__module__}.{func.__name__}"
                        
                        # Track failure count
                        self.failure_counts[func_name] = self.failure_counts.get(func_name, 0) + 1
                        
                        if attempt < max_retries:
                            delay = min(base_delay * (2 ** attempt), max_delay)
                            self.logger.warning(
                                f"Function {func_name} failed (attempt {attempt + 1}/{max_retries + 1}), retrying in {delay:.1f}s",
                                {'function': func_name, 'attempt': attempt + 1, 'error': str(e), 'delay': delay}
                            )
                            import time
                            time.sleep(delay)
                        else:
                            self.logger.error(
                                f"Function {func_name} failed after {max_retries + 1} attempts",
                                {'function': func_name, 'total_attempts': max_retries + 1, 'final_error': str(e)}
                            )
                
                raise last_exception
            return wrapper
        return decorator
    
    def circuit_breaker(self, failure_threshold: int = 5, recovery_timeout: float = 300):
        """Circuit breaker pattern to prevent cascading failures"""
        def decorator(func: F) -> F:
            func_name = f"{func.__module__}.{func.__name__}"
            state = {'failures': 0, 'last_failure': 0, 'state': 'closed'}  # closed, open, half-open
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                import time
                now = time.time()
                
                # Check circuit state
                if state['state'] == 'open':
                    if now - state['last_failure'] > recovery_timeout:
                        state['state'] = 'half-open'
                        self.logger.info(f"Circuit breaker for {func_name} moving to half-open state")
                    else:
                        raise SecurityTestingError(f"Circuit breaker open for {func_name}")
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Success - reset or close circuit
                    if state['state'] in ['half-open', 'open']:
                        self.logger.info(f"Circuit breaker for {func_name} closing (success)")
                    state['failures'] = 0
                    state['state'] = 'closed'
                    
                    return result
                    
                except Exception as e:
                    state['failures'] += 1
                    state['last_failure'] = now
                    
                    if state['failures'] >= failure_threshold:
                        state['state'] = 'open'
                        self.logger.error(
                            f"Circuit breaker opened for {func_name} after {failure_threshold} failures",
                            {'function': func_name, 'failures': state['failures']}
                        )
                    
                    raise
            
            return wrapper
        return decorator


class SafeExecutor:
    """Safe execution context with enhanced error handling"""
    
    def __init__(self, logger: EnhancedLogger, recovery_manager: ErrorRecoveryManager):
        self.logger = logger
        self.recovery_manager = recovery_manager
    
    def execute_with_fallback(self, primary_func: Callable, fallback_funcs: list, *args, **kwargs):
        """Execute function with fallback options"""
        functions_to_try = [primary_func] + fallback_funcs
        
        for i, func in enumerate(functions_to_try):
            try:
                self.logger.debug(f"Attempting execution with {func.__name__}")
                result = func(*args, **kwargs)
                
                if i > 0:  # Used a fallback
                    self.logger.warning(f"Primary function failed, succeeded with fallback: {func.__name__}")
                
                return result
                
            except Exception as e:
                if i == len(functions_to_try) - 1:  # Last function failed
                    self.logger.error(f"All execution attempts failed, last error from {func.__name__}: {e}")
                    raise
                else:
                    self.logger.warning(f"Function {func.__name__} failed, trying fallback: {e}")
        
        raise SecurityTestingError("No valid execution path found")
    
    def safe_call(self, func: Callable, default_return=None, suppress_exceptions=True, *args, **kwargs):
        """Safely call a function with optional exception suppression"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.logger.error(f"Safe call to {func.__name__} failed: {e}")
            if suppress_exceptions:
                return default_return
            raise


# Global instances for easy access
enhanced_logger = EnhancedLogger()
recovery_manager = ErrorRecoveryManager(enhanced_logger)
safe_executor = SafeExecutor(enhanced_logger, recovery_manager)

# Convenience decorators
retry_on_failure = recovery_manager.retry_with_exponential_backoff
circuit_breaker = recovery_manager.circuit_breaker


def safe_execute(
    default: Any = None,
    error_msg: str = "Operation failed",
    log_level: str = "ERROR",
    raise_on_error: bool = False
) -> Callable[[F], F]:
    """
    Decorator for safe function execution with enhanced error handling
    
    Args:
        default: Default value to return on error
        error_msg: Error message prefix
        log_level: Logging level for errors
        raise_on_error: Whether to raise exception after logging
    
    Returns:
        Decorated function with error handling
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except KeyboardInterrupt:
                enhanced_logger.log("Operation interrupted by user", "INFO")
                raise
            except Exception as e:
                error_context = {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()) if kwargs else []
                }
                
                enhanced_logger.set_context(**error_context)
                enhanced_logger.log_exception(e, f"{error_msg} in {func.__name__}")
                enhanced_logger.clear_context()
                
                if raise_on_error:
                    raise
                    
                return default
                
        return wrapper
    return decorator


def validate_input(
    value: Any,
    validators: Dict[str, Any],
    field_name: str = "input"
) -> bool:
    """
    Enhanced input validation with multiple checks
    
    Args:
        value: Value to validate
        validators: Dictionary of validation rules
        field_name: Name of field being validated
    
    Returns:
        True if validation passes
        
    Raises:
        ValidationError: If validation fails
    """
    errors = []
    
    # Type validation
    if "type" in validators:
        expected_type = validators["type"]
        if not isinstance(value, expected_type):
            errors.append(f"{field_name} must be of type {expected_type.__name__}")
    
    # String-specific validations
    if isinstance(value, str):
        # Length validation
        if "max_length" in validators:
            max_len = validators["max_length"]
            if len(value) > max_len:
                errors.append(f"{field_name} exceeds maximum length of {max_len}")
        
        if "min_length" in validators:
            min_len = validators["min_length"]
            if len(value) < min_len:
                errors.append(f"{field_name} below minimum length of {min_len}")
        
        # Pattern validation
        if "pattern" in validators:
            pattern = validators["pattern"]
            # Handle both string patterns and compiled regex objects
            if isinstance(pattern, str):
                import re
                pattern = re.compile(pattern)
            if not pattern.match(value):
                errors.append(f"{field_name} does not match required pattern")
        
        # Forbidden content
        if "forbidden" in validators:
            forbidden = validators["forbidden"]
            for forbidden_item in forbidden:
                if forbidden_item.lower() in value.lower():
                    errors.append(f"{field_name} contains forbidden content: {forbidden_item}")
    
    # Numeric validations
    if isinstance(value, (int, float)):
        if "min_value" in validators:
            min_val = validators["min_value"]
            if value < min_val:
                errors.append(f"{field_name} below minimum value of {min_val}")
        
        if "max_value" in validators:
            max_val = validators["max_value"]
            if value > max_val:
                errors.append(f"{field_name} exceeds maximum value of {max_val}")
    
    # Empty value check
    if "allow_empty" in validators and not validators["allow_empty"]:
        if not value or (isinstance(value, str) and not value.strip()):
            errors.append(f"{field_name} cannot be empty")
    
    if errors:
        raise ValidationError(f"Validation failed for {field_name}: {'; '.join(errors)}")
    
    return True


@safe_execute(default=False, error_msg="File operation failed")
def safe_file_write(file_path: Path, content: str, encoding: str = "utf-8") -> bool:
    """
    Safely write content to file with error handling
    
    Args:
        file_path: Path to write to
        content: Content to write
        encoding: File encoding
        
    Returns:
        True if successful, False otherwise
    """
    # Input validation
    validate_input(str(file_path), {
        "type": str,
        "max_length": 1000,
        "forbidden": ["..", "/etc/", "/root/", "/bin/"]
    }, "file_path")
    
    validate_input(content, {
        "type": str,
        "max_length": 10 * 1024 * 1024  # 10MB limit
    }, "content")
    
    # Ensure parent directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Atomic write operation
    with open(file_path, 'w', encoding=encoding) as f:
        f.write(content)
    
    enhanced_logger.log(f"Successfully wrote file: {file_path}", "DEBUG")
    return True


@safe_execute(default=None, error_msg="File read failed")
def safe_file_read(file_path: Path, encoding: str = "utf-8") -> Optional[str]:
    """
    Safely read file content with error handling
    
    Args:
        file_path: Path to read from
        encoding: File encoding
        
    Returns:
        File content or None on error
    """
    if not file_path.exists():
        enhanced_logger.log(f"File not found: {file_path}", "WARNING")
        return None
    
    if not file_path.is_file():
        enhanced_logger.log(f"Path is not a file: {file_path}", "WARNING") 
        return None
    
    # Check file size (limit to 50MB)
    if file_path.stat().st_size > 50 * 1024 * 1024:
        enhanced_logger.log(f"File too large to read: {file_path}", "WARNING")
        return None
    
    with open(file_path, 'r', encoding=encoding) as f:
        content = f.read()
    
    enhanced_logger.log(f"Successfully read file: {file_path}", "DEBUG")
    return content


class ErrorRecovery:
    """Error recovery and retry mechanisms"""
    
    @staticmethod
    def retry_operation(
        func: Callable,
        max_attempts: int = 3,
        delay_seconds: float = 1.0,
        backoff_factor: float = 2.0,
        exceptions: tuple = (Exception,)
    ) -> Any:
        """
        Retry operation with exponential backoff
        
        Args:
            func: Function to retry
            max_attempts: Maximum retry attempts
            delay_seconds: Initial delay between retries
            backoff_factor: Backoff multiplier
            exceptions: Exceptions to catch and retry on
            
        Returns:
            Function result
            
        Raises:
            Last exception if all retries fail
        """
        import time
        
        last_exception = None
        delay = delay_seconds
        
        for attempt in range(max_attempts):
            try:
                return func()
            except exceptions as e:
                last_exception = e
                
                if attempt < max_attempts - 1:
                    enhanced_logger.log(
                        f"Retry attempt {attempt + 1}/{max_attempts} after {delay}s delay",
                        "WARNING",
                        error=str(e)
                    )
                    time.sleep(delay)
                    delay *= backoff_factor
                else:
                    enhanced_logger.log(
                        f"All retry attempts failed for operation",
                        "ERROR",
                        attempts=max_attempts,
                        final_error=str(e)
                    )
        
        if last_exception:
            raise last_exception

# Enhanced recovery strategies
class AdvancedErrorRecovery:
    """Advanced error recovery with multiple strategies"""
    
    def __init__(self):
        self.recovery_strategies = {}
        self.fallback_handlers = {}
    
    def register_fallback(self, operation: str, fallback_func: Callable):
        """Register a fallback function for an operation"""
        self.fallback_handlers[operation] = fallback_func
    
    def safe_execute(self, operation: str, func: Callable, *args, **kwargs):
        """Execute function with multiple recovery strategies"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            enhanced_logger.warning(f"Operation {operation} failed: {str(e)}")
            
            # Try fallback if available
            if operation in self.fallback_handlers:
                try:
                    enhanced_logger.info(f"Attempting fallback for {operation}")
                    return self.fallback_handlers[operation](*args, **kwargs)
                except Exception as fallback_e:
                    enhanced_logger.error(f"Fallback for {operation} also failed: {str(fallback_e)}")
            
            # Log and re-raise if no fallback available
            enhanced_logger.error(f"No recovery possible for {operation}")
            raise

# Global recovery manager instance
advanced_recovery = AdvancedErrorRecovery()
circuit_breaker = recovery_manager.circuit_breaker