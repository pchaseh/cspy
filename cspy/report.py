from pydantic import BaseModel, Field, AliasChoices, ConfigDict
from pydantic.alias_generators import to_camel as to_camel_
from typing import Literal


def hyphenize(field: str) -> str:
    return field.replace("_", "-")


def to_camel(field: str) -> str:
    return to_camel_(field).replace("Url", "URL")


class CspReportBodyCommon(BaseModel):
    blocked_url: str = Field(validation_alias=AliasChoices("blocked-uri", "blockedURL"))
    disposition: Literal["enforce", "report"]
    document_url: str = Field(
        validation_alias=AliasChoices("document-uri", "documentURL")
    )
    effective_directive: str = Field(
        validation_alias=AliasChoices("effective-directive", "effectiveDirective")
    )
    original_policy: str = Field(
        validation_alias=AliasChoices("original-policy", "originalPolicy")
    )
    referrer: str | None = None
    sample: str | None = Field(
        default=None, validation_alias=AliasChoices("sample", "scriptSample")
    )
    status_code: int = Field(validation_alias=AliasChoices("status-code", "statusCode"))


class CspReportCommon(BaseModel):
    """
    Defines Content Security Policy report fields shared by both the legacy (report-uri)
    and current (report-to) directives
    """

    body: CspReportBodyCommon = Field(
        validation_alias=AliasChoices("csp-report", "body")
    )


class LegacyCspReportBody(BaseModel):
    blocked_uri: str
    disposition: Literal["enforce", "report"]
    document_uri: str
    effective_directive: str
    original_policy: str
    referrer: str | None = None
    script_sample: str | None = None
    status_code: int
    violated_directive: str

    model_config = ConfigDict(alias_generator=hyphenize)


class LegacyCspReport(BaseModel):
    """
    Defines the structure for Content Security Policy (CSP) reports received
    when the report-uri directive is in use
    """

    csp_report: LegacyCspReportBody

    model_config = ConfigDict(alias_generator=hyphenize)


class CspViolationReportBody(BaseModel):
    blocked_url: str
    column_number: int
    disposition: Literal["enforce", "report"]
    document_url: str
    effective_directive: str
    line_number: int
    original_policy: str
    referrer: str | None = None
    sample: str | None = None
    source_file: str | None = None
    status_code: int

    model_config = ConfigDict(alias_generator=to_camel)


class CspReport(BaseModel):
    """
    Defines the structure for Content Security Policy (CSP) reports received
    when the report-to directive is in use
    """

    type_field: Literal["csp-violation"] = Field(validation_alias="type")
    url: str
    user_agent: str | None = None
    age: int | None = None
    body: CspViolationReportBody
