# ApiPosture

[![Build and Test](https://github.com/BlagoCuljak/ApiPosture.Python/actions/workflows/ci.yml/badge.svg)](https://github.com/BlagoCuljak/ApiPosture.Python/actions/workflows/ci.yml)
[![PyPI Version](https://img.shields.io/pypi/v/apiposture?logo=pypi&label=PyPI)](https://pypi.org/project/apiposture)
[![PyPI Downloads](https://img.shields.io/pypi/dm/apiposture?logo=pypi&label=Downloads)](https://pypi.org/project/apiposture)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-support-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/blagoculjak)

A CLI security inspection tool for Python API frameworks. Performs static source-code analysis to identify authorization misconfigurations and security risks.

### Terminal Output

![Terminal Output](assets/images/Python1_result.webp)

### Findings Report

![Findings Report](assets/images/Python2_result.webp)

## Features

- **Multi-Framework Support**: FastAPI, Flask, Django REST Framework
- **8 Security Rules**: Comprehensive detection of common authorization issues
- **Multiple Output Formats**: Terminal (Rich), JSON, Markdown
- **Configurable**: YAML-based configuration with suppressions
- **CI/CD Ready**: Exit codes based on severity for pipeline integration

## Installation

```bash
pip install apiposture
```

## Quick Start

```bash
# Scan current directory
apiposture scan .

# Scan specific path with JSON output
apiposture scan ./src --output json

# Scan and fail on high severity findings (for CI)
apiposture scan . --fail-on high
```

## Security Rules

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| AP001 | Public without explicit intent | High | Public endpoint without AllowAny or explicit marker |
| AP002 | Anonymous on write | High | AllowAny on POST/PUT/DELETE/PATCH |
| AP003 | Auth conflict | Medium | Method-level AllowAny overrides class auth |
| AP004 | Missing auth on writes | Critical | No auth on write endpoints |
| AP005 | Excessive roles | Low | >3 roles on single endpoint |
| AP006 | Weak role naming | Low | Generic names like "user", "admin" |
| AP007 | Sensitive keywords | Medium | admin/debug/export in public routes |
| AP008 | Endpoint without auth | High | No auth configuration at all |

## Supported Frameworks

### FastAPI

```python
from fastapi import Depends, FastAPI

@app.get("/protected")
async def protected(user = Depends(get_current_user)):
    ...
```

### Flask

```python
from flask import Flask
from flask_login import login_required

@app.route("/protected")
@login_required
def protected():
    ...
```

### Django REST Framework

```python
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]
```

## Configuration

Create `.apiposture.yaml` in your project root:

```yaml
rules:
  disabled:
    - AP006  # Disable weak role naming check

exclude:
  - "**/tests/**"
  - "**/migrations/**"

suppressions:
  - rule: AP001
    route: "/health"
    reason: "Health check is intentionally public"
```

## CLI Options

```
apiposture scan [PATH] [OPTIONS]

Options:
  -o, --output         Output format: terminal, json, markdown
  -f, --output-file    Write output to file
  -c, --config         Configuration file path
  --severity           Minimum severity: info, low, medium, high, critical
  --fail-on            Exit code 1 if findings at this severity
  --sort-by            Sort by: severity, route, method, classification
  --classification     Filter: public, authenticated, role_restricted
  --method             Filter: GET, POST, PUT, DELETE, PATCH
  --route-contains     Filter routes by substring
  --framework          Filter: fastapi, flask, django_drf
  --rule               Filter by rule ID
  --no-color           Disable colored output
  --no-icons           Disable icons
```

## Development

```bash
# Clone the repository
git clone https://github.com/apiposture/apiposture-python
cd apiposture-python

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src tests

# Run type checker
mypy src
```

## License

MIT
