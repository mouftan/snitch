## Installation

1. **Clone the repository**
    ```bash
    git clone 
    cd snitch
    ```

2. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

Run the tool and follow the interactive prompts:

```bash
python snitch.py
```

- Enter the target URL when prompted (e.g., `https://example.com`).
- The tool will automatically:
    - Detect technologies
    - Scan for sensitive files and directories
    - Brute-force common directories
    - Discover API endpoints
    - Analyze PHP info pages
    - Detect known vulnerabilities (CVEs)
    - Generate a JSON report with all findings

