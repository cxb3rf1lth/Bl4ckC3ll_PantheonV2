#!/usr/bin/env python3
"""
Performance Tester
Runs performance benchmarks and validates performance requirements
"""

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import psutil


class PerformanceTester:
    def __init__(self):
        self.results = {}
        self.benchmarks = []

    def measure_startup_time(self) -> float:
        """Measure application startup time"""
        start_time = time.time()
        try:
            result = subprocess.run(
                ["python3", "bl4ckc3ll_p4nth30n.py", "--help"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            end_time = time.time()
            if result.returncode == 0:
                return end_time - start_time
        except subprocess.TimeoutExpired:
            return float("inf")
        return float("inf")

    def measure_memory_usage(self) -> Dict[str, float]:
        """Measure memory usage during basic operations"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / (1024 * 1024)  # MB

        # Run a basic operation
        try:
            subprocess.run(
                ["python3", "bl4ckc3ll_p4nth30n.py", "--check-tools"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            pass

        peak_memory = process.memory_info().rss / (1024 * 1024)  # MB

        return {
            "initial_memory_mb": initial_memory,
            "peak_memory_mb": peak_memory,
            "memory_increase_mb": peak_memory - initial_memory,
        }

    def measure_test_suite_performance(self) -> Dict[str, float]:
        """Measure test suite execution time"""
        start_time = time.time()
        try:
            result = subprocess.run(
                ["python3", "enhanced_test_suite.py"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            end_time = time.time()

            if result.returncode == 0:
                return {
                    "execution_time": end_time - start_time,
                    "tests_per_second": 16 / (end_time - start_time),  # 16 tests total
                }
        except subprocess.TimeoutExpired:
            return {"execution_time": float("inf"), "tests_per_second": 0}

        return {"execution_time": float("inf"), "tests_per_second": 0}

    def measure_file_operations(self) -> Dict[str, float]:
        """Measure file I/O performance"""
        test_file = Path("/tmp/perf_test.txt")

        # Write test
        start_time = time.time()
        with open(test_file, "w") as f:
            for i in range(10000):
                f.write(f"Test line {i}\n")
        write_time = time.time() - start_time

        # Read test
        start_time = time.time()
        with open(test_file, "r") as f:
            lines = f.readlines()
        read_time = time.time() - start_time

        # Cleanup
        test_file.unlink()

        return {
            "write_time": write_time,
            "read_time": read_time,
            "lines_written": 10000,
            "lines_read": len(lines),
        }

    def validate_performance_requirements(self) -> List[str]:
        """Validate performance against requirements"""
        issues = []

        # Performance requirements
        requirements = {
            "startup_time_max": 5.0,  # seconds
            "memory_increase_max": 100.0,  # MB
            "test_suite_time_max": 60.0,  # seconds
            "file_write_time_max": 2.0,  # seconds
            "file_read_time_max": 1.0,  # seconds
        }

        # Check startup time
        if self.results.get("startup_time", 0) > requirements["startup_time_max"]:
            issues.append(
                f"PERFORMANCE: Startup time {self.results['startup_time']:.2f}s exceeds maximum {requirements['startup_time_max']}s"
            )

        # Check memory usage
        memory_increase = self.results.get("memory_usage", {}).get(
            "memory_increase_mb", 0
        )
        if memory_increase > requirements["memory_increase_max"]:
            issues.append(
                f"PERFORMANCE: Memory increase {memory_increase:.2f}MB exceeds maximum {requirements['memory_increase_max']}MB"
            )

        # Check test suite performance
        test_time = self.results.get("test_suite_performance", {}).get(
            "execution_time", 0
        )
        if test_time > requirements["test_suite_time_max"]:
            issues.append(
                f"PERFORMANCE: Test suite time {test_time:.2f}s exceeds maximum {requirements['test_suite_time_max']}s"
            )

        # Check file operations
        file_ops = self.results.get("file_operations", {})
        if file_ops.get("write_time", 0) > requirements["file_write_time_max"]:
            issues.append(
                f"PERFORMANCE: File write time {file_ops['write_time']:.2f}s exceeds maximum {requirements['file_write_time_max']}s"
            )

        if file_ops.get("read_time", 0) > requirements["file_read_time_max"]:
            issues.append(
                f"PERFORMANCE: File read time {file_ops['read_time']:.2f}s exceeds maximum {requirements['file_read_time_max']}s"
            )

        return issues

    def run_all_benchmarks(self) -> int:
        """Run all performance benchmarks"""
        print("⚡ Running Performance Benchmarks...")

        # Measure startup time
        print("  📊 Measuring startup time...")
        self.results["startup_time"] = self.measure_startup_time()

        # Measure memory usage
        print("  🧠 Measuring memory usage...")
        self.results["memory_usage"] = self.measure_memory_usage()

        # Measure test suite performance
        print("  🧪 Measuring test suite performance...")
        self.results["test_suite_performance"] = self.measure_test_suite_performance()

        # Measure file operations
        print("  📁 Measuring file I/O performance...")
        self.results["file_operations"] = self.measure_file_operations()

        # Validate against requirements
        issues = self.validate_performance_requirements()

        # Report results
        print("\n📊 Performance Results:")
        print(f"  ⏱️  Startup time: {self.results['startup_time']:.2f}s")
        print(
            f"  🧠 Memory usage: {self.results['memory_usage']['memory_increase_mb']:.2f}MB increase"
        )
        print(
            f"  🧪 Test suite: {self.results['test_suite_performance']['execution_time']:.2f}s"
        )
        print(
            f"  📁 File I/O: {self.results['file_operations']['write_time']:.2f}s write, {self.results['file_operations']['read_time']:.2f}s read"
        )

        if issues:
            print(f"\n⚠️  Found {len(issues)} performance issues:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("\n✅ All performance benchmarks passed!")

        # Save detailed report
        with open("performance-report.json", "w") as f:
            json.dump(
                {"results": self.results, "issues": issues, "timestamp": time.time()},
                f,
                indent=2,
            )

        return len(issues)


if __name__ == "__main__":
    tester = PerformanceTester()
    issues = tester.run_all_benchmarks()
    sys.exit(1 if issues > 0 else 0)
