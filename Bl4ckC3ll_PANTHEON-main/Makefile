# Bl4ckC3ll_PANTHEON Makefile
# Convenience targets for common operations

.PHONY: help install quickstart test clean diagnostics run update

help:	## Show this help message
	@echo "Bl4ckC3ll_PANTHEON - Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:	## Run full installation
	@echo "Running automated installation..."
	@chmod +x install.sh
	@./install.sh

quickstart:	## Quick start with automated setup
	@echo "Running quick start..."
	@chmod +x quickstart.sh
	@./quickstart.sh

test:		## Test installation and run diagnostics
	@echo "Running installation tests..."
	@python3 test_installation.py 2>/dev/null || echo "test_installation.py not found, running diagnostics instead"
	@python3 diagnostics.py

diagnostics:	## Run detailed system diagnostics
	@python3 diagnostics.py

run:		## Run the main application
	@python3 bl4ckc3ll_p4nth30n.py

deps:		## Install Python dependencies only
	@echo "Installing Python dependencies..."
	@python3 -m pip install --upgrade pip --user
	@python3 -m pip install -r requirements.txt --user

tools:		## Install Go security tools only
	@echo "Installing Go security tools..."
	@go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	@go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	@go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	@go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	@go install github.com/projectdiscovery/katana/cmd/katana@latest
	@go install github.com/lc/gau/v2/cmd/gau@latest

update:		## Update security tools and templates
	@echo "Updating security tools..."
	@go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	@go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	@go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	@go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	@go install github.com/projectdiscovery/katana/cmd/katana@latest
	@go install github.com/lc/gau/v2/cmd/gau@latest
	@nuclei -update-templates 2>/dev/null || echo "Nuclei not found or update failed"

clean:		## Clean up generated files and directories
	@echo "Cleaning up..."
	@rm -rf runs/* || true
	@rm -rf logs/*.log || true
	@rm -rf external_lists/* || true
	@rm -rf lists_merged/* || true
	@rm -rf __pycache__ || true
	@rm -f .setup_complete || true
	@rm -f .write_test || true
	@echo "Cleanup complete"

reset:		## Reset to fresh installation state
	@echo "Resetting to fresh state..."
	@$(MAKE) clean
	@rm -f .setup_complete
	@echo "example.com" > targets.txt
	@echo "Reset complete. Run 'make install' to reinstall."

version:	## Show version information
	@echo "Bl4ckC3ll_PANTHEON version information:"
	@python3 -c "import sys; print(f'Python: {sys.version}')"
	@go version 2>/dev/null || echo "Go: Not installed"
	@echo "Script version: $(shell grep 'VERSION.*=' bl4ckc3ll_p4nth30n.py | head -1 | cut -d'"' -f2)"

status:		## Show installation status
	@echo "Installation status:"
	@python3 diagnostics.py | grep -E "✓|✗" | head -20