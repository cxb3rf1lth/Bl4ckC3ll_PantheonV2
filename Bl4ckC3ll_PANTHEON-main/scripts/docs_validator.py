#!/usr/bin/env python3
"""
Documentation Validator
Validates documentation files for consistency and quality
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List


class DocumentationValidator:
    def __init__(self):
        self.issues = []

    def validate_markdown(self, file_path: Path) -> List[str]:
        """Validate markdown files"""
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Check for broken links
            links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)
            for link_text, link_url in links:
                if link_url.startswith("http"):
                    # External links - just warn if they look suspicious
                    if not re.match(r"^https?://", link_url):
                        issues.append(
                            f"WARNING: Suspicious external link in {file_path}: {link_url}"
                        )
                elif link_url.startswith("/") or link_url.startswith("./"):
                    # Internal links - check if file exists
                    target_path = Path(link_url.lstrip("./"))
                    if not target_path.exists():
                        issues.append(
                            f"ERROR: Broken internal link in {file_path}: {link_url}"
                        )

            # Check for TODO/FIXME comments
            todo_pattern = r"(TODO|FIXME|XXX|HACK):"
            todos = re.findall(todo_pattern, content, re.IGNORECASE)
            if todos:
                issues.append(
                    f"INFO: Found {len(todos)} TODO/FIXME items in {file_path}"
                )

            # Check for proper heading structure
            headings = re.findall(r"^(#{1,6})\s+(.+)$", content, re.MULTILINE)
            if headings:
                heading_levels = [len(h[0]) for h in headings]
                for i in range(1, len(heading_levels)):
                    if heading_levels[i] > heading_levels[i - 1] + 1:
                        issues.append(
                            f"WARNING: Heading level skip in {file_path} (line with '{headings[i][1]}')"
                        )

            # Check for code blocks without language specification
            code_blocks = re.findall(r"```(\w*)\n", content)
            for block in code_blocks:
                if not block:
                    issues.append(
                        f"WARNING: Code block without language specification in {file_path}"
                    )

        except Exception as e:
            issues.append(f"ERROR: Could not validate {file_path}: {e}")

        return issues

    def validate_rst(self, file_path: Path) -> List[str]:
        """Validate reStructuredText files"""
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Check for basic RST syntax issues
            if ".. " in content:
                # Check for common directive issues
                directives = re.findall(r"\.\. (\w+)::", content)
                known_directives = [
                    "note",
                    "warning",
                    "code-block",
                    "image",
                    "figure",
                    "table",
                ]
                for directive in directives:
                    if directive not in known_directives:
                        issues.append(
                            f"WARNING: Unknown RST directive '{directive}' in {file_path}"
                        )

        except Exception as e:
            issues.append(f"ERROR: Could not validate {file_path}: {e}")

        return issues

    def check_documentation_completeness(self) -> List[str]:
        """Check if documentation is complete"""
        issues = []

        # Required documentation files
        required_docs = [
            "README.md",
            "USAGE_GUIDE.md",
            "SECURITY_CHECKLIST.md",
            "CHANGELOG.md",
        ]

        for doc in required_docs:
            if not Path(doc).exists():
                issues.append(f"ERROR: Missing required documentation: {doc}")
            else:
                # Check if file is not empty
                with open(doc, "r", encoding="utf-8") as f:
                    if len(f.read().strip()) < 100:
                        issues.append(
                            f"WARNING: Documentation file {doc} seems incomplete (too short)"
                        )

        return issues

    def validate_all(self) -> int:
        """Validate all documentation files"""
        print("📚 Running Documentation Validation...")

        # Get all documentation files
        md_files = list(Path(".").glob("**/*.md"))
        rst_files = list(Path(".").glob("**/*.rst"))

        total_issues = 0

        # Validate Markdown files
        for file_path in md_files:
            if ".git" in str(file_path):
                continue
            issues = self.validate_markdown(file_path)
            self.issues.extend(issues)
            total_issues += len(issues)

        # Validate RST files
        for file_path in rst_files:
            if ".git" in str(file_path):
                continue
            issues = self.validate_rst(file_path)
            self.issues.extend(issues)
            total_issues += len(issues)

        # Check completeness
        completeness_issues = self.check_documentation_completeness()
        self.issues.extend(completeness_issues)
        total_issues += len(completeness_issues)

        # Report results
        if total_issues == 0:
            print("✅ Documentation validation passed - no issues found!")
        else:
            print(f"⚠️  Found {total_issues} documentation issues:")
            for issue in self.issues:
                print(f"  - {issue}")

        # Save report
        with open("docs-validation-report.json", "w") as f:
            json.dump(
                {
                    "total_issues": total_issues,
                    "issues": self.issues,
                    "files_checked": {"markdown": len(md_files), "rst": len(rst_files)},
                },
                f,
                indent=2,
            )

        return total_issues


if __name__ == "__main__":
    validator = DocumentationValidator()
    issues = validator.validate_all()
    sys.exit(1 if issues > 0 else 0)
