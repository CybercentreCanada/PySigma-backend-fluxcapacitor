from sigma.backends.flux import FluxBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_get_unavailable_parent_fields(flux: FluxBackend):
    assert flux.get_correlated_fields("process_creation") == {"ParentCommandLine"}
    assert flux.get_correlated_fields("webserver") == {"ParentCommandLine"}


class TestCorrelation:
    discrete_rule = SigmaRule.from_yaml(
        """\
title: Discrete Rule
logsource:
  category: webserver
  product: windows
detection:
  selection:
    CommandLine|contains:
      - ".doc.lnk"
      - ".docx.lnk"
      - ".pdf.lnk"
  condition: selection"""
    )
    flux_rule = SigmaRule.from_yaml(
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
  condition: pr_selection"""
    )

    test_rules = SigmaCollection([discrete_rule, flux_rule])

    def test_correlated(self, flux: FluxBackend):
        assert not flux.correlated(
            self.discrete_rule.detection.detections["selection"], self.discrete_rule.logsource.category
        )
        assert flux.correlated(
            self.flux_rule.detection.detections["pr_selection"],
            self.flux_rule.logsource.category,
        )

    def test_has_correlated_detection(self, flux: FluxBackend):
        assert not flux.has_correlated_detection(self.discrete_rule)
        assert flux.has_correlated_detection(self.flux_rule)

    def test_convert_flux_spec_generation(self, flux: FluxBackend):
        output = flux.convert(self.test_rules)
        assert "source" in flux.last_processing_pipeline.state
        assert isinstance(output, list)
        assert len(output) == 3

        pre, post, spec = output
        assert isinstance(pre, str)
        assert isinstance(post, str)
        assert isinstance(spec, str)

        assert (
            pre
            == """\
SELECT
    *,
    map(
        'Discrete Rule',
        map(
            'selection',
            CommandLine ILIKE '%.doc.lnk%' OR CommandLine ILIKE '%.docx.lnk%' OR CommandLine ILIKE '%.pdf.lnk%'
        ),
        'Suspicious Double File Extension in ParentCommandLine',
        map(
            'pr_selection',
            CommandLine ILIKE '%.doc.lnk%' OR CommandLine ILIKE '%.docx.lnk%' OR CommandLine ILIKE '%.pdf.lnk%'
        )
    ) as sigma
    FROM
(
SELECT
    *
FROM
    table
)
"""
        )

        assert (
            post
            == """\
SELECT
    *,
    map_keys(
    map_filter(
    map(
        'Discrete Rule',
        (sigma['Discrete Rule']['selection']),
        'Suspicious Double File Extension in ParentCommandLine',
        (sigma['Suspicious Double File Extension in ParentCommandLine']['pr_selection'])
    )
    , (k,v) -> v = TRUE)) as sigma_final
FROM
    table_flux_output_0
"""
        )
        assert (
            spec
            == """\
rules:
    - rulename: Suspicious Double File Extension in ParentCommandLine
      description: None
      action: parent
      parent: parent_oid
      child: child_oid
      tags:
        - name: pr_selection
"""
        )


# the backend shouldn't alias Foo.Bar to Foo_Bar if the struct problem get fixed in the flux-capacitor scala code
def test_struct_column_access(flux: FluxBackend):
    discrete_rule = SigmaRule.from_yaml(
        """\
title: Discrete Rule
logsource:
  category: webserver
  product: windows
detection:
  selection:
    Nested: value
  condition: selection"""
    )

    pre, post, spec = flux.convert(SigmaCollection([discrete_rule]))
    assert (
        pre
        == """\
SELECT
    *,
    map(
        'Discrete Rule',
        map(
            'selection',
            Struct_tag ILIKE 'value'
        )
    ) as sigma
    FROM
(
SELECT
    Struct.tag AS Struct_tag,
    *
FROM
    table
)
"""
    )
