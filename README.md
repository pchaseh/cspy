# cspy

Content Security Policy parsing utilities

## Install
```bash
pip install git+https://github.com/pchaseh/cspy
```

## Usage
Parsing a serialized Content Security Policy:
```python
from cspy.policy import parse_serialized_csp

print(parse_serialized_csp("default-src 'self' example.com;"))
```

Output:
```python
{'default-src': ["'self'", 'example.com']}
```

Parsing a CSP report:
```python
from cspy.report import CspReportCommon

json_body = {
    "csp-report": {
        "blocked-uri": "http://example.com/css/style.css",
        "disposition": "report",
        "document-uri": "http://example.com/signup.html",
        "effective-directive": "style-src-elem",
        "original-policy": "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
        "referrer": "",
        "status-code": 200,
        "violated-directive": "style-src-elem",
    }
}
print(CspReportCommon.model_validate(json_body))
```

Output:
```python
body=CspReportBodyCommon(blocked_url='http://example.com/css/style.css', disposition='report', document_url='http://example.com/signup.html', effective_directive='style-src-elem', original_policy="default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports", referrer='', sample=None, status_code=200)
```

In the above example, we are using the `CspReportCommon` which is suitable for both reports generated through the Reporting API (`report-to` directive) and the legacy CSP reporting (`report-uri` directive). If you require access to the full structure, use `CspReport` or `LegacyCspReport` accordingly.
