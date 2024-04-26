from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.conversion.base import ProcessingPipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem
from sigma.processing.transformations import (
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.rule import SigmaRule

from sigma.backends.flux import FluxBackend

test_mappings: dict[str, str | list[str]] = {
    "Nested": "Struct.tag",
    "CommandLine": "CommandLine",
    "ParentCommandLine": "CommandLine",
    "ParentProcessOID": "ParentProcessOID",
}

logsource_category_info: dict[str, dict[str, str | set[str]]] = {
    "process_creation": {
        "view": "view",
        "table": "table",
        "correlated_fields": {"ParentCommandLine"},
    },
    "webserver": {
        "view": "view",
        "table": "table",
        "correlated_fields": {"ParentCommandLine"},
    },
}


@pytest.fixture
def pipeline() -> ProcessingPipeline:
    p = ProcessingPipeline(
        name="pipeline",
        items=[
            ProcessingItem(
                identifier="process_creation_mapping",
                transformation=FieldMappingTransformation(test_mappings),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            ),
            ProcessingItem(
                identifier="process_creation_set_source",
                transformation=SetStateTransformation("source", logsource_category_info.get("process_creation", {})),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            ),
            ProcessingItem(
                identifier="webserver_mapping",
                transformation=FieldMappingTransformation(test_mappings),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
            ProcessingItem(
                identifier="webserver_set_source",
                transformation=SetStateTransformation("source", logsource_category_info.get("webserver", {})),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
        ],
    )
    p.state = {"logsource_category_info": logsource_category_info}
    return p


@pytest.fixture
def flux(pipeline: ProcessingPipeline) -> FluxBackend:
    return FluxBackend(processing_pipeline=pipeline)


@pytest.fixture
def tests_dir() -> Path:
    return Path(__file__).parent


@pytest.fixture
def test_rules(tests_dir: Path) -> SigmaCollection:
    return SigmaCollection(
        [
            SigmaRule.from_yaml(rule)
            for rule in [
                """\
title: Suspicious Double File Extension in ParentCommandLine
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  pr_selection:
    ParentCommandLine|contains:
      - ".doc.lnk"
      - ".docx.lnk"
      - ".pdf.lnk"
  condition: selection""",
                """\
title: Test1
logsource:
  category: webserver
  product: windows
detection:
  selection:
    CommandLine|contains:
      - ".doc.lnk"
      - ".docx.lnk"
      - ".pdf.lnk"
  condition: selection""",
            ]
        ]
    )
