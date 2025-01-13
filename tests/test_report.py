from cspy.report import (
    LegacyCspReport,
    CspReport,
    CspReportCommon,
    hyphenize,
    to_camel,
)


def test_parse_legacy_csp_report() -> None:
    json_body = {
        "csp-report": {
            "blocked-uri": "http://example.com/css/style.css",
            "disposition": "report",
            "document-uri": "http://example.com/signup.html",
            "effective-directive": "style-src-elem",
            "original-policy": "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",  # noqa: E501
            "referrer": "",
            "status-code": 200,
            "violated-directive": "style-src-elem",
        }
    }
    parsed = LegacyCspReport.model_validate(json_body)
    dumped = LegacyCspReport.model_dump(parsed, exclude_unset=True)

    for k, v in dumped["csp_report"].items():
        assert json_body["csp-report"][hyphenize(k)] == v


def test_csp_report() -> None:
    json_body = {
        "age": 53531,
        "body": {
            "blockedURL": "inline",
            "columnNumber": 39,
            "disposition": "enforce",
            "documentURL": "https://example.com/csp-report",
            "effectiveDirective": "script-src-elem",
            "lineNumber": 121,
            "originalPolicy": "default-src 'self'; report-to csp-endpoint-name",
            "referrer": "https://www.google.com/",
            "sample": 'console.log("lo")',
            "sourceFile": "https://example.com/csp-report",
            "statusCode": 200,
        },
        "type": "csp-violation",
        "url": "https://example.com/csp-report",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",  # noqa: E501
    }

    parsed = CspReport.model_validate(json_body)
    dumped = parsed.model_dump(exclude_unset=True)

    for k, v in dumped["body"].items():
        assert json_body["body"][to_camel(k)] == v  # type: ignore[index]


def test_csp_report_common() -> None:
    legacy = {
        "age": 53531,
        "body": {
            "blockedURL": "inline",
            "columnNumber": 39,
            "disposition": "enforce",
            "documentURL": "https://example.com/csp-report",
            "effectiveDirective": "script-src-elem",
            "lineNumber": 121,
            "originalPolicy": "default-src 'self'; report-to csp-endpoint-name",
            "referrer": "https://www.google.com/",
            "sample": 'console.log("lo")',
            "sourceFile": "https://example.com/csp-report",
            "statusCode": 200,
        },
        "type": "csp-violation",
        "url": "https://example.com/csp-report",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",  # noqa: E501
    }

    new = {
        "csp-report": {
            "blocked-uri": "http://example.com/css/style.css",
            "disposition": "report",
            "document-uri": "http://example.com/signup.html",
            "effective-directive": "style-src-elem",
            "original-policy": "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",  # noqa: E501
            "referrer": "",
            "status-code": 200,
            "violated-directive": "style-src-elem",
        }
    }

    _ = CspReportCommon.model_validate(legacy)
    _ = CspReportCommon.model_validate(new)
