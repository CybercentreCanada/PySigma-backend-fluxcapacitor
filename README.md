## pySigma-backend-fluxcapacitor
## Description
This is a Spark SQL backend for pySigma for use with flux-capacitor. It provides the package `sigma.backends.flux` with the `FluxBackend` class.

## Installation
It is recommended to create a python venv in the root folder of the repo:
```bash
git clone git@gitlab.chimera.cyber.gc.ca:CCCSA/pysigma-backend-fluxcapacitor.git
cd pysigma-backend-fluxcapacitor
python -m venv .venv
source .venv/bin/activate
```
Since [`pysigma-backend-spark`](https://gitlab.chimera.cyber.gc.ca/CCCSA/pysigma-backend-spark) is not yet in the bag of holding,
it will need to installed in the virtual environment using the following commands:
```bash
cd ..
git clone git@gitlab.chimera.cyber.gc.ca:CCCSA/pysigma-backend-spark.git
pip install pysigma-backend-spark
```

Now, you can install the project:
```bash
cd pysigma-backend-fluxcapacitor
pip install .
```
`-e` can be added before `.` to install in editable mode and `[dev]` can be added directly after `.` to install dev dependencies.
```bash
pip install -e .[dev]
```

## Example Usage
```python
from sigma.backends.flux import FluxBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    SetStateTransformation,
)

test_mappings: dict[str, str | list[str]] = {
    "CommandLine": "CommandLine",
    "ParentCommandLine": "CommandLine",
}


def pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="pipeline",
        items=[
            ProcessingItem(identifier="test_mapping", transformation=FieldMappingTransformation(test_mappings)),
            ProcessingItem(
                identifier="set_source",
                transformation=SetStateTransformation(
                    key="source", val={x: x for x in ["view", "table", "hash_column", "parent_hash_column"]}
                ),
            ),
        ],
    )


rule = SigmaCollection.from_yaml(
    """\
title: Test
logsource:
    category: test
    product: windows
detection:
    selection:
        CommandLine: value1
    pr_selection:
        ParentCommandLine|contains: value2
    condition: selection
"""
)
pre_flux, post_flux, spec_yml = FluxBackend(processing_pipeline=pipeline()).convert(rule)
assert (
    pre_flux
    == """\
SELECT
    *,
    map(
        'Test',
        map(
            'selection',
            CommandLine ILIKE 'value1',
            'pr_selection',
            CommandLine ILIKE '%value2%'
        )
    ) as sigma_pre_flux
    FROM
(
SELECT
    hash_column AS oid,
    parent_hash_column AS parent_oid,
    *
FROM
    table
)
"""
)

assert (
    post_flux
    == """\
SELECT
    *,
    map_keys(
    map_filter(
    map(
        'Test',
        (sigma['Test']['selection'])
    )
    , (k,v) -> v = TRUE)) as sigma_final
FROM
    table_flux_output_0
"""
), post_flux

assert (
    spec_yml
    == """\
rules:
    - rulename: Test
      description: None
      action: parent
      parent: parent_oid
      child: oid
      tags:
        - name: pr_selection
"""
)
```