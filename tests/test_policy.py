from cspy.policy import parse_serialized_csp, override_policy_directives
import pytest


@pytest.mark.parametrize(
    "value, expected_result",
    [
        ("", {}),
        (" ", {}),
        ("   ", {}),
    ],
)
def test_parse_serialized_csp_blank(value: str, expected_result: dict[str, list[str]]):
    assert parse_serialized_csp(value) == expected_result


@pytest.mark.parametrize(
    "value, expected_result",
    [
        ("default-src", {"default-src": []}),
        (" default-src", {"default-src": []}),
        ("default-src ", {"default-src": []}),
        (" default-src ", {"default-src": []}),
        ("default-src;", {"default-src": []}),
        ("default-src ;", {"default-src": []}),
    ],
)
def test_parse_serialized_csp_one_directive_no_value(
    value: str, expected_result: dict[str, list[str]]
):
    assert parse_serialized_csp(value) == expected_result


@pytest.mark.parametrize(
    "value, expected_result",
    [
        ("default-src example.com", {"default-src": ["example.com"]}),
        (" default-src example.com", {"default-src": ["example.com"]}),
        ("default-src  example.com", {"default-src": ["example.com"]}),
        (" default-src example.com", {"default-src": ["example.com"]}),
        ("default-src example.com;", {"default-src": ["example.com"]}),
        ("default-src example.com ;", {"default-src": ["example.com"]}),
    ],
)
def test_parse_serialized_csp_one_directive_one_value(
    value: str, expected_result: dict[str, list[str]]
):
    assert parse_serialized_csp(value) == expected_result


@pytest.mark.parametrize(
    "value, expected_result",
    [
        ("default-src 'self' example.com", {"default-src": ["'self'", "example.com"]}),
        (" default-src 'self' example.com", {"default-src": ["'self'", "example.com"]}),
        ("default-src  'self' example.com", {"default-src": ["'self'", "example.com"]}),
        (" default-src 'self' example.com", {"default-src": ["'self'", "example.com"]}),
        ("default-src 'self' example.com;", {"default-src": ["'self'", "example.com"]}),
        (
            "default-src 'self' example.com ;",
            {"default-src": ["'self'", "example.com"]},
        ),
    ],
)
def test_parse_serialized_csp_one_directive_two_values(
    value: str, expected_result: dict[str, list[str]]
):
    assert parse_serialized_csp(value) == expected_result


@pytest.mark.parametrize(
    "value, expected_result",
    [
        (
            "default-src example.com; script-src 'self'; default-src ignored.com",
            {"default-src": ["example.com"], "script-src": ["'self'"]},
        ),
        (
            " default-src example.com; script-src 'self'; default-src ignored.com",
            {"default-src": ["example.com"], "script-src": ["'self'"]},
        ),
        (
            "default-src example.com ; script-src 'self'; default-src ignored.com",
            {"default-src": ["example.com"], "script-src": ["'self'"]},
        ),
        (
            "default-src example.com ; script-src 'self'; default-src ignored.com",
            {"default-src": ["example.com"], "script-src": ["'self'"]},
        ),
    ],
)
def test_parse_serialized_csp_duplicate_directive_loose(
    value: str, expected_result: dict[str, list[str]]
):
    assert parse_serialized_csp(value) == expected_result


@pytest.mark.parametrize(
    "value",
    [
        ("default-src example.com; script-src 'self'; default-src ignored.com"),
        (" default-src example.com; script-src 'self'; default-src ignored.com"),
        ("default-src example.com ; script-src 'self'; default-src ignored.com"),
        ("default-src example.com ; script-src 'self'; default-src ignored.com"),
    ],
)
def test_parse_serialized_csp_duplicate_directive_strict(value: str):
    with pytest.raises(ValueError, match="duplicate directive 'default-src'"):
        parse_serialized_csp(value, strict=True)


@pytest.mark.parametrize(
    "value, expected_result",
    [
        ("DEFAULT-SRC EXAMPLE.COM", {"default-src": ["EXAMPLE.COM"]}),
        ("dEfAuLt-SrC example.com", {"default-src": ["example.com"]}),
    ],
)
def test_parse_serialized_csp_case_insensitive(
    value: str, expected_result: dict[str, list[str]]
):
    assert parse_serialized_csp(value) == expected_result


@pytest.mark.parametrize(
    "value",
    [
        ("default-src example.com; unknown-src 'self'"),
    ],
)
def test_parse_serialized_csp_unknown_directive(value: str):
    with pytest.raises(ValueError, match="unknown directive 'unknown-src'"):
        parse_serialized_csp(value, strict=True)


@pytest.mark.parametrize(
    "value, expected_result",
    [
        (
            "default-src example.com; custom-src 'self'",
            {"default-src": ["example.com"], "custom-src": ["'self'"]},
        ),
    ],
)
def test_parse_serialized_csp_override(
    value: str, expected_result: dict[str, list[str]]
):
    override_policy_directives({"default-src", "custom-src"})
    assert parse_serialized_csp(value) == expected_result
