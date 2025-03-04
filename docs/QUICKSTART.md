# GitHubScan Quick Start Guide

This guide will help you get started with GitHubScan quickly.

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/GitHubScan.git
   cd GitHubScan
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python githubscan.py --help
   ```

## Basic Usage

### Scan a Public Repository

```bash
python githubscan.py https://github.com/username/repo
```

This will:
- Clone the repository
- Scan for vulnerabilities
- Generate a PDF report (default)

### Scan a Private Repository

```bash
python githubscan.py https://github.com/username/private-repo --token YOUR_GITHUB_TOKEN
```

## Common Use Cases

### 1. Generate a PDF Security Report

```bash
python githubscan.py https://github.com/username/repo --output-format pdf --output-file security-report.pdf
```

### 2. Interactive Remediation Session

```bash
python githubscan.py https://github.com/username/repo --interactive
```

This will guide you through each vulnerability with:
- Severity information
- Code context
- Remediation suggestions

### 3. CI/CD Integration

```bash
python githubscan.py https://github.com/username/repo --output-format sarif --min-severity high --ci-mode
```

This will:
- Generate a SARIF report for GitHub Code Scanning
- Only include high and critical issues
- Exit with non-zero code if issues are found

### 4. Generate GitHub Actions Workflow

```bash
python githubscan.py --generate-workflow
```

This creates a `.github/workflows/security-scan.yml` file for automated scanning.

## Filtering Results

You can filter results by severity level:

```bash
python githubscan.py https://github.com/username/repo --min-severity medium
```

Severity levels (from highest to lowest):
- `critical`
- `high`
- `medium`
- `low`
- `info`

## Output Formats

GitHubScan supports multiple output formats:

- `pdf`: Professional report with executive summary (default)
- `sarif`: For GitHub Code Scanning integration
- `json`: Structured data for programmatic processing
- `csv`: For spreadsheet analysis
- `text`: Simple text output

Example:
```bash
python githubscan.py https://github.com/username/repo --output-format json --output-file results.json
```

## Next Steps

- Check the [README.md](../README.md) for complete documentation
- Explore the [example workflow](example-workflow.yml) for CI/CD integration
- Customize the tool for your specific security requirements 