# Multi-stage build for Bl4ckC3ll_PANTHEON Security Scanner
FROM golang:1.21-alpine AS go-builder

# Install git for go modules
RUN apk add --no-cache git

# Install Go-based security tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/owasp-amass/amass/v4/cmd/amass@master && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/haccer/subjack@latest

# Main application stage
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    dnsutils \
    whois \
    openssl \
    nmap \
    masscan \
    dirb \
    nikto \
    sqlmap \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder stage
COPY --from=go-builder /go/bin/* /usr/local/bin/

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make scripts executable
RUN chmod +x bl4ckc3ll_p4nth30n.py cicd_integration.py diagnostics.py install.sh quickstart.sh

# Create necessary directories
RUN mkdir -p runs logs plugins external_lists lists_merged wordlists_extra payloads exploits backups

# Update Nuclei templates
RUN nuclei -update-templates || true

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import bl4ckc3ll_p4nth30n; print('OK')" || exit 1

# Default command
CMD ["python3", "bl4ckc3ll_p4nth30n.py"]

# Labels for metadata
LABEL maintainer="@cxb3rf1lth"
LABEL description="Bl4ckC3ll_PANTHEON - Advanced Security Testing Framework"
LABEL version="9.0.0-enhanced"
LABEL org.opencontainers.image.source="https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON"