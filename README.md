# GitHubScan

<div align="center">
  
![GitHub Scan Logo](https://img.shields.io/badge/GitHub-Scan-blue?style=for-the-badge&logo=github)

**A comprehensive security scanning tool for GitHub repositories**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

</div>

## 🔍 Overview

GitHubScan is a powerful security scanning tool designed to identify vulnerabilities, secrets, compliance issues, and security misconfigurations in GitHub repositories. It performs comprehensive analysis across multiple languages, frameworks, and infrastructure-as-code files to provide actionable security insights.

## ✨ Features

### 🛡️ Comprehensive Security Scanning
- **Multi-language Support**: Python, JavaScript, Ruby, PHP, PowerShell, Shell, Go, Java, C#, and more
- **Secret Detection**: API keys, tokens, credentials, and other sensitive information
- **Dependency Analysis**: Vulnerable dependencies in package.json, requirements.txt, and Gemfile.lock
- **Git History Analysis**: Detect secrets committed in the past
- **License Compliance**: Identify license issues and compatibility problems
- **Infrastructure-as-Code Scanning**: Terraform, CloudFormation, and Kubernetes security issues
- **Web Framework Configurations**: Django, Flask, Express.js, Spring Boot, Rails security misconfigurations

### 📊 Advanced Reporting
- **Multiple Output Formats**: PDF, JSON, CSV, text, and SARIF
- **Severity Classification**: Critical, High, Medium, Low, and Info levels
- **Risk Scoring**: Prioritize findings based on risk
- **Remediation Suggestions**: Actionable advice for fixing issues

### 🔄 CI/CD Integration
- **GitHub Actions Support**: Automated workflow generation
- **Configurable Exit Codes**: Control build failures based on severity
- **SARIF Integration**: Compatible with GitHub Code Scanning

### 👨‍💻 Developer Experience
- **Interactive Mode**: Review and remediate issues one by one
- **Code Context**: See vulnerable code in context
- **Detailed Explanations**: Understand why issues are flagged

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/GitHubScan.git
cd GitHubScan

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Basic Usage
```bash
python githubscan.py https://github.com/username/repo
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `repo_url` | GitHub repository URL (e.g., https://github.com/user/repo.git) |
| `--token` | GitHub token for private repositories |
| `--output-format` | Output format: text, json, csv, pdf, sarif (default: pdf) |
| `--output-file` | File to save output (defaults: report.pdf for PDF, report.sarif for SARIF) |
| `--min-severity` | Minimum severity level: critical, high, medium, low, info (default: low) |
| `--ci-mode` | CI mode: exit with non-zero code if issues found |
| `--fail-on-severity` | In CI mode, exit with error if issues of this severity or higher are found (default: high) |
| `--generate-workflow` | Generate a GitHub Actions workflow file for automated scanning |
| `--workflow-path` | Path for the generated GitHub Actions workflow file |
| `--interactive` | Interactive mode: review issues one by one with remediation suggestions |

### Examples

#### Generate a PDF Report
```bash
python githubscan.py https://github.com/username/repo --output-format pdf --output-file security-report.pdf
```

#### CI/CD Integration
```bash
python githubscan.py https://github.com/username/repo --output-format sarif --min-severity medium --ci-mode
```

#### Interactive Remediation
```bash
python githubscan.py https://github.com/username/repo --interactive
```

#### Generate GitHub Actions Workflow
```bash
python githubscan.py --generate-workflow
```

## 🔧 Advanced Configuration

### Customizing Severity Thresholds
You can customize which issues are reported by setting the minimum severity level:

```bash
# Only show critical and high severity issues
python githubscan.py https://github.com/username/repo --min-severity high
```

### CI/CD Pipeline Integration
For CI/CD pipelines, you can configure the tool to fail builds based on severity:

```bash
# Fail the build if any critical issues are found
python githubscan.py https://github.com/username/repo --ci-mode --fail-on-severity critical
```

## 📋 Supported Vulnerability Types

- **Code Injection**: eval(), exec(), system() calls
- **Hardcoded Credentials**: API keys, passwords, tokens
- **Insecure Configurations**: Debug modes, disabled security features
- **Dependency Issues**: Outdated or vulnerable packages
- **Infrastructure Risks**: Public S3 buckets, open security groups
- **License Compliance**: Missing or incompatible licenses
- **Web Security**: XSS, CSRF, insecure cookies
- **And many more...**

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [ReportLab](https://www.reportlab.com/) - PDF generation
- [Bandit](https://github.com/PyCQA/bandit) - Python security linter
- [ShellCheck](https://www.shellcheck.net/) - Shell script analysis
- [ESLint](https://eslint.org/) - JavaScript linting
- [RuboCop](https://rubocop.org/) - Ruby code analyzer
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) - PowerShell script analyzer 