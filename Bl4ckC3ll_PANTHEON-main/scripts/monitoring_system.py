#!/usr/bin/env python3
"""
Comprehensive Monitoring and Alerting System
Continuously monitors repository health, performance, and security
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests


class MonitoringSystem:
    def __init__(self):
        self.config = self._load_config()
        self.state = self._load_state()
        self.alerts = []
        self.metrics = {}

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("monitoring.log"),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def _load_config(self) -> Dict[str, Any]:
        """Load monitoring configuration"""
        default_config = {
            "monitoring": {
                "enabled": True,
                "interval_seconds": 300,  # 5 minutes
                "alert_thresholds": {
                    "cpu_usage": 80,
                    "memory_usage": 85,
                    "disk_usage": 90,
                    "test_failure_rate": 20,
                    "security_score": 80,
                },
            },
            "alerts": {
                "email_enabled": False,
                "webhook_enabled": False,
                "slack_enabled": False,
                "console_enabled": True,
            },
            "metrics": {
                "collect_system_metrics": True,
                "collect_git_metrics": True,
                "collect_test_metrics": True,
                "collect_security_metrics": True,
                "retention_days": 30,
            },
        }

        config_file = Path("monitoring-config.json")
        if config_file.exists():
            try:
                with open(config_file, "r") as f:
                    user_config = json.load(f)
                # Merge configs
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
            except Exception as e:
                print(f"Warning: Could not load monitoring config: {e}")

        return default_config

    def _load_state(self) -> Dict[str, Any]:
        """Load monitoring state"""
        default_state = {
            "last_check": None,
            "metrics_history": [],
            "alerts_history": [],
            "performance_baseline": {},
        }

        state_file = Path("monitoring-state.json")
        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load monitoring state: {e}")

        return default_state

    def _save_state(self):
        """Save monitoring state"""
        try:
            with open("monitoring-state.json", "w") as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Could not save monitoring state: {e}")

    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(".")

            return {
                "timestamp": datetime.now().isoformat(),
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_usage": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
            }
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {e}")
            return {}

    def collect_git_metrics(self) -> Dict[str, Any]:
        """Collect Git repository metrics"""
        try:
            # Get git status
            result = subprocess.run(
                ["git", "status", "--porcelain"], capture_output=True, text=True
            )
            uncommitted_files = (
                len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0
            )

            # Get commit count
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"], capture_output=True, text=True
            )
            total_commits = int(result.stdout.strip()) if result.returncode == 0 else 0

            # Get recent commits
            result = subprocess.run(
                ["git", "log", "--oneline", "--since=24 hours ago"],
                capture_output=True,
                text=True,
            )
            recent_commits = (
                len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0
            )

            # Get branch info
            result = subprocess.run(
                ["git", "branch", "-r"], capture_output=True, text=True
            )
            remote_branches = (
                len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0
            )

            return {
                "timestamp": datetime.now().isoformat(),
                "uncommitted_files": uncommitted_files,
                "total_commits": total_commits,
                "recent_commits_24h": recent_commits,
                "remote_branches": remote_branches,
            }
        except Exception as e:
            self.logger.error(f"Failed to collect git metrics: {e}")
            return {}

    def collect_test_metrics(self) -> Dict[str, Any]:
        """Collect test execution metrics"""
        try:
            # Run quick test suite
            start_time = time.time()
            result = subprocess.run(
                [sys.executable, "enhanced_test_suite.py"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            execution_time = time.time() - start_time

            test_success = result.returncode == 0

            # Parse test output for more details
            test_count = 0
            failures = 0
            if "tests passed" in result.stdout:
                # Extract numbers from output
                import re

                match = re.search(r"(\d+)/(\d+) tests passed", result.stdout)
                if match:
                    test_count = int(match.group(2))
                    passed = int(match.group(1))
                    failures = test_count - passed

            return {
                "timestamp": datetime.now().isoformat(),
                "test_success": test_success,
                "execution_time": execution_time,
                "total_tests": test_count,
                "failed_tests": failures,
                "success_rate": (
                    ((test_count - failures) / test_count * 100)
                    if test_count > 0
                    else 0
                ),
            }
        except subprocess.TimeoutExpired:
            return {
                "timestamp": datetime.now().isoformat(),
                "test_success": False,
                "execution_time": 120,
                "error": "Test execution timed out",
            }
        except Exception as e:
            self.logger.error(f"Failed to collect test metrics: {e}")
            return {"timestamp": datetime.now().isoformat(), "error": str(e)}

    def collect_security_metrics(self) -> Dict[str, Any]:
        """Collect security metrics"""
        try:
            # Run security validator
            result = subprocess.run(
                [sys.executable, "scripts/security_validator.py"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            security_issues = result.returncode

            # Try to parse JSON output if available
            security_details = {}
            if Path("security-validation-report.json").exists():
                try:
                    with open("security-validation-report.json", "r") as f:
                        security_details = json.load(f)
                except Exception:
                    pass

            return {
                "timestamp": datetime.now().isoformat(),
                "security_check_passed": result.returncode == 0,
                "security_issues_count": security_issues,
                "security_score": max(0, 100 - security_issues * 5),  # Simple scoring
                "details": security_details,
            }
        except Exception as e:
            self.logger.error(f"Failed to collect security metrics: {e}")
            return {"timestamp": datetime.now().isoformat(), "error": str(e)}

    def analyze_metrics_trends(self, metrics: Dict[str, Any]) -> List[str]:
        """Analyze metrics for trends and anomalies"""
        trends = []

        # Check against baselines
        baseline = self.state.get("performance_baseline", {})

        if "cpu_usage" in metrics and "cpu_usage" in baseline:
            if metrics["cpu_usage"] > baseline["cpu_usage"] * 1.5:
                trends.append(
                    f"CPU usage significantly higher than baseline: {metrics['cpu_usage']:.1f}% vs {baseline['cpu_usage']:.1f}%"
                )

        if "memory_usage" in metrics and "memory_usage" in baseline:
            if metrics["memory_usage"] > baseline["memory_usage"] * 1.3:
                trends.append(
                    f"Memory usage significantly higher than baseline: {metrics['memory_usage']:.1f}% vs {baseline['memory_usage']:.1f}%"
                )

        # Check recent history for patterns
        history = self.state.get("metrics_history", [])
        if len(history) >= 5:
            recent_metrics = history[-5:]

            # Check for consistent degradation
            cpu_values = [
                m.get("cpu_usage", 0) for m in recent_metrics if "cpu_usage" in m
            ]
            if len(cpu_values) >= 3 and all(
                cpu_values[i] < cpu_values[i + 1] for i in range(len(cpu_values) - 1)
            ):
                trends.append("CPU usage showing consistent upward trend")

            memory_values = [
                m.get("memory_usage", 0) for m in recent_metrics if "memory_usage" in m
            ]
            if len(memory_values) >= 3 and all(
                memory_values[i] < memory_values[i + 1]
                for i in range(len(memory_values) - 1)
            ):
                trends.append("Memory usage showing consistent upward trend")

        return trends

    def check_alert_conditions(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if any alert conditions are met"""
        alerts = []
        thresholds = self.config["monitoring"]["alert_thresholds"]

        # System resource alerts
        if metrics.get("cpu_usage", 0) > thresholds["cpu_usage"]:
            alerts.append(
                {
                    "level": "warning",
                    "type": "system",
                    "message": f"High CPU usage: {metrics['cpu_usage']:.1f}%",
                    "value": metrics["cpu_usage"],
                    "threshold": thresholds["cpu_usage"],
                }
            )

        if metrics.get("memory_usage", 0) > thresholds["memory_usage"]:
            alerts.append(
                {
                    "level": "warning",
                    "type": "system",
                    "message": f"High memory usage: {metrics['memory_usage']:.1f}%",
                    "value": metrics["memory_usage"],
                    "threshold": thresholds["memory_usage"],
                }
            )

        if metrics.get("disk_usage", 0) > thresholds["disk_usage"]:
            alerts.append(
                {
                    "level": "critical",
                    "type": "system",
                    "message": f"High disk usage: {metrics['disk_usage']:.1f}%",
                    "value": metrics["disk_usage"],
                    "threshold": thresholds["disk_usage"],
                }
            )

        # Test failure alerts
        if "success_rate" in metrics and metrics["success_rate"] < (
            100 - thresholds["test_failure_rate"]
        ):
            alerts.append(
                {
                    "level": "critical",
                    "type": "tests",
                    "message": f"High test failure rate: {100 - metrics['success_rate']:.1f}%",
                    "value": metrics["success_rate"],
                    "threshold": 100 - thresholds["test_failure_rate"],
                }
            )

        # Security alerts
        if (
            "security_score" in metrics
            and metrics["security_score"] < thresholds["security_score"]
        ):
            alerts.append(
                {
                    "level": "critical",
                    "type": "security",
                    "message": f"Low security score: {metrics['security_score']:.1f}",
                    "value": metrics["security_score"],
                    "threshold": thresholds["security_score"],
                }
            )

        return alerts

    def send_alerts(self, alerts: List[Dict[str, Any]]):
        """Send alerts through configured channels"""
        if not alerts:
            return

        alert_config = self.config["alerts"]

        # Console alerts
        if alert_config["console_enabled"]:
            for alert in alerts:
                level_emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
                emoji = level_emoji.get(alert["level"], "📢")
                self.logger.warning(
                    f"{emoji} {alert['level'].upper()}: {alert['message']}"
                )

        # TODO: Implement other alert channels
        if alert_config["email_enabled"]:
            self._send_email_alerts(alerts)

        if alert_config["webhook_enabled"]:
            self._send_webhook_alerts(alerts)

        if alert_config["slack_enabled"]:
            self._send_slack_alerts(alerts)

    def _send_email_alerts(self, alerts: List[Dict[str, Any]]):
        """Send email alerts (placeholder)"""
        # Implementation would require email configuration
        self.logger.info(f"Would send {len(alerts)} email alerts")

    def _send_webhook_alerts(self, alerts: List[Dict[str, Any]]):
        """Send webhook alerts (placeholder)"""
        # Implementation would require webhook URL configuration
        self.logger.info(f"Would send {len(alerts)} webhook alerts")

    def _send_slack_alerts(self, alerts: List[Dict[str, Any]]):
        """Send Slack alerts (placeholder)"""
        # Implementation would require Slack webhook URL
        self.logger.info(f"Would send {len(alerts)} Slack alerts")

    def update_performance_baseline(self, metrics: Dict[str, Any]):
        """Update performance baseline with current metrics"""
        baseline = self.state.get("performance_baseline", {})

        # Update baseline with exponential smoothing
        alpha = 0.1  # Smoothing factor

        for key in ["cpu_usage", "memory_usage", "execution_time"]:
            if key in metrics:
                if key in baseline:
                    baseline[key] = alpha * metrics[key] + (1 - alpha) * baseline[key]
                else:
                    baseline[key] = metrics[key]

        self.state["performance_baseline"] = baseline

    def cleanup_old_data(self):
        """Clean up old monitoring data"""
        retention_days = self.config["metrics"]["retention_days"]
        cutoff_date = datetime.now() - timedelta(days=retention_days)

        # Clean metrics history
        history = self.state.get("metrics_history", [])
        self.state["metrics_history"] = [
            m
            for m in history
            if datetime.fromisoformat(m.get("timestamp", "1970-01-01")) > cutoff_date
        ]

        # Clean alerts history
        alerts_history = self.state.get("alerts_history", [])
        self.state["alerts_history"] = [
            a
            for a in alerts_history
            if datetime.fromisoformat(a.get("timestamp", "1970-01-01")) > cutoff_date
        ]

    def run_monitoring_cycle(self) -> Dict[str, Any]:
        """Run a complete monitoring cycle"""
        cycle_start = time.time()
        self.logger.info("Starting monitoring cycle")

        # Collect all metrics
        all_metrics = {"timestamp": datetime.now().isoformat()}

        if self.config["metrics"]["collect_system_metrics"]:
            system_metrics = self.collect_system_metrics()
            all_metrics.update(system_metrics)

        if self.config["metrics"]["collect_git_metrics"]:
            git_metrics = self.collect_git_metrics()
            all_metrics.update(git_metrics)

        if self.config["metrics"]["collect_test_metrics"]:
            test_metrics = self.collect_test_metrics()
            all_metrics.update(test_metrics)

        if self.config["metrics"]["collect_security_metrics"]:
            security_metrics = self.collect_security_metrics()
            all_metrics.update(security_metrics)

        # Analyze trends
        trends = self.analyze_metrics_trends(all_metrics)

        # Check for alerts
        alerts = self.check_alert_conditions(all_metrics)

        # Send alerts
        if alerts:
            self.send_alerts(alerts)

        # Update state
        self.state["last_check"] = datetime.now().isoformat()
        self.state["metrics_history"].append(all_metrics)
        if alerts:
            self.state["alerts_history"].extend(alerts)

        # Update baseline
        self.update_performance_baseline(all_metrics)

        # Cleanup old data
        self.cleanup_old_data()

        # Save state
        self._save_state()

        cycle_duration = time.time() - cycle_start

        cycle_summary = {
            "duration": cycle_duration,
            "metrics_collected": len(all_metrics),
            "trends_detected": len(trends),
            "alerts_triggered": len(alerts),
            "overall_health": "healthy" if len(alerts) == 0 else "degraded",
        }

        self.logger.info(
            f"Monitoring cycle completed in {cycle_duration:.2f}s - "
            f"Health: {cycle_summary['overall_health']}, "
            f"Alerts: {len(alerts)}"
        )

        return cycle_summary

    def generate_monitoring_report(self) -> str:
        """Generate comprehensive monitoring report"""
        history = self.state.get("metrics_history", [])
        recent_alerts = self.state.get("alerts_history", [])
        baseline = self.state.get("performance_baseline", {})

        report = f"""# 📊 Repository Monitoring Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## 🏥 Current Health Status

"""

        # Recent metrics
        if history:
            latest = history[-1]
            report += f"""### Latest Metrics
- **CPU Usage**: {latest.get('cpu_usage', 'N/A')}%
- **Memory Usage**: {latest.get('memory_usage', 'N/A')}%
- **Disk Usage**: {latest.get('disk_usage', 'N/A')}%
- **Test Success Rate**: {latest.get('success_rate', 'N/A')}%
- **Security Score**: {latest.get('security_score', 'N/A')}

"""

        # Recent alerts
        recent_24h = [
            a
            for a in recent_alerts
            if datetime.fromisoformat(a.get("timestamp", "1970-01-01"))
            > datetime.now() - timedelta(hours=24)
        ]

        report += f"""## 🚨 Recent Alerts (24h)

Found {len(recent_24h)} alerts in the last 24 hours:

"""

        for alert in recent_24h[-10:]:  # Show last 10 alerts
            report += f"- **{alert.get('level', 'unknown').upper()}**: {alert.get('message', 'No message')}\n"

        if not recent_24h:
            report += "✅ No alerts in the last 24 hours\n"

        # Performance trends
        report += f"""
## 📈 Performance Trends

### Baseline Values
"""
        for key, value in baseline.items():
            report += f"- **{key.replace('_', ' ').title()}**: {value:.2f}\n"

        # Historical data summary
        if len(history) >= 24:  # If we have at least 24 data points
            recent_24 = history[-24:]
            avg_cpu = sum(m.get("cpu_usage", 0) for m in recent_24) / len(recent_24)
            avg_memory = sum(m.get("memory_usage", 0) for m in recent_24) / len(
                recent_24
            )

            report += f"""
### 24-Hour Averages
- **Average CPU Usage**: {avg_cpu:.1f}%
- **Average Memory Usage**: {avg_memory:.1f}%
"""

        # Recommendations
        report += """
## 🎯 Recommendations

"""
        if recent_24h:
            report += "- Address recent alerts to improve system health\n"
            report += "- Monitor resource usage closely\n"
        else:
            report += "- System appears healthy - continue regular monitoring\n"

        report += "- Review performance trends for optimization opportunities\n"
        report += "- Ensure automated backups are functioning\n"
        report += "- Keep dependencies updated for security\n"

        return report

    def run_continuous_monitoring(self):
        """Run continuous monitoring loop"""
        self.logger.info("Starting continuous monitoring system")

        if not self.config["monitoring"]["enabled"]:
            self.logger.info("Monitoring is disabled in configuration")
            return

        interval = self.config["monitoring"]["interval_seconds"]

        try:
            while True:
                self.run_monitoring_cycle()

                # Generate and save report
                report = self.generate_monitoring_report()
                with open("monitoring-report.md", "w") as f:
                    f.write(report)

                self.logger.info(f"Sleeping for {interval} seconds...")
                time.sleep(interval)

        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring system error: {e}")
            raise


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Repository Monitoring System")
    parser.add_argument(
        "--once", action="store_true", help="Run monitoring once and exit"
    )
    parser.add_argument(
        "--report", action="store_true", help="Generate report and exit"
    )

    args = parser.parse_args()

    monitor = MonitoringSystem()

    if args.report:
        report = monitor.generate_monitoring_report()
        print(report)
        with open("monitoring-report.md", "w") as f:
            f.write(report)
        print("\nReport saved to monitoring-report.md")
    elif args.once:
        summary = monitor.run_monitoring_cycle()
        print(f"Monitoring cycle completed: {summary}")
    else:
        monitor.run_continuous_monitoring()


if __name__ == "__main__":
    main()
