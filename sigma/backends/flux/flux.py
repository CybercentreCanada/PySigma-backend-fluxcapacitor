import copy
from collections import ChainMap
from itertools import chain
from typing import Any, ClassVar, NamedTuple, Union

from sigma.backends.spark import SourceType, SparkSQLBackend
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
    ConditionType,
    ConditionValueExpression,
    SigmaCondition,
)
from sigma.conversion.base import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaDetectionError, SigmaError
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaDetections, SigmaRule
from sigma.types import SpecialChars

from .spec import SpecFields
from .utils import alter_nested_fields, get_first

PostfluxConditionType = type[ConditionIdentifier | ConditionSelector | ConditionType]


class PreFlux(NamedTuple):
    body: str
    altered_fields: dict[str, str]
    logsource_category: str | None


class Flux(NamedTuple):
    pre: PreFlux
    post: str
    spec: str


class FluxBackend(SparkSQLBackend):
    """Flux Spark SQL backend."""

    name: ClassVar[str] = "Flux Spark SQL Backend"
    identifier = "flux"
    formats: ClassVar[dict[str, str]] = {
        "default": "Pre_flux SQL, post_flux SQL, and spec YML",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pipeline_mappings: dict[str, dict[str, str]] = (
            {
                item.identifier.removesuffix("_mapping"): {
                    field: column
                    for field, columns in item.transformation.mapping.items()
                    if (column := get_first(columns)) is not None
                }
                for item in self.processing_pipeline.items
                if isinstance(item.transformation, FieldMappingTransformation) and item.identifier is not None
            }
            if self.processing_pipeline is not None
            else {}
        )

    def get_mapping(self, logsource_category: str | None) -> dict[str, str]:
        if logsource_category is not None:
            return self.pipeline_mappings.get(logsource_category, {})
        return {}

    def get_correlated_fields(self, logsource_category: str | None) -> set[str]:
        return (
            self.processing_pipeline.state.get("logsource_category_info", {})
            .get(logsource_category, {})
            .get("correlated_fields", set())
        )

    def correlated(self, item: SigmaDetection | SigmaDetectionItem, logsource_category: str | None) -> bool:
        if isinstance(item, SigmaDetectionItem):
            return item.field in self.get_correlated_fields(logsource_category)
        elif isinstance(item, SigmaDetection):
            correlation_results = {self.correlated(item, logsource_category) for item in item.detection_items}
            if correlation_results == {True, False}:
                raise SigmaDetectionError("Cannot mix child and parent fields in detection")
            return correlation_results == {True}
        else:
            raise TypeError(f"expected SigmaDetection | SigmaDetectionItem, got {item.__class__.__name__}")

    def has_correlated_detection(self, rule: SigmaRule) -> bool:
        return any(self.correlated(item, rule.logsource.category) for item in rule.detection.detections.values())

    def convert(
        self,
        rule_collection: SigmaCollection,
        output_format: str | None = None,
        source_type: SourceType = SourceType.TABLE,
        index: int = 0,
    ) -> list[str]:
        queries = [query for rule in rule_collection.rules if (query := self.convert_rule(rule)) is not None]
        return self.finalize_output_flux(queries=queries, index=index, source_type=source_type)

    def convert_rule(self, rule: SigmaRule, *args, **kwargs) -> Flux | None:
        rule = copy.deepcopy(rule)
        try:
            # generate spec before applying pipeline
            error_state = "generating flux spec for"
            parent_action_tags = "\n".join(
                f"- name: {name}"
                for name, det in rule.detection.detections.items()
                if self.correlated(det, rule.logsource.category)
            )

            spec = (
                f"""\
- rulename: {rule.title}
  description: {rule.description}
  action: parent
  parent: {SpecFields.PARENT}
  child: {SpecFields.CHILD}
  tags:
{self.indent_block(parent_action_tags, 4)}"""
                if parent_action_tags
                else ""
            )

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline = self.backend_processing_pipeline + self.processing_pipeline
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations

            # 2. Convert conditions
            error_state = "converting"
            states = [
                ConversionState(processing_state=dict(self.last_processing_pipeline.state))
                for _ in rule.detection.parsed_condition
            ]
            feature_states = [
                ConversionState(processing_state=dict(self.last_processing_pipeline.state))
                for _ in rule.detection.detections
            ]

            # workaround for using nested fields since flux-capacitor doesn't support them at the moment
            altered_fields = alter_nested_fields(rule)

            features = [
                (
                    cond,
                    self.convert_condition(SigmaCondition(cond, rule.detection).parse(), feature_states[index]),
                )
                for index, cond in enumerate(rule.detection.detections)
            ]
            rule_name = self.escape_string(rule.title)
            formatted_features = ",\n".join(f"'{name}',\n{query}" for name, query in features)

            pre_flux = PreFlux(
                body=f"{self.quote_string(rule_name)},\nmap(\n{self.indent_block(formatted_features, 4)}\n)",
                altered_fields=altered_fields,
                logsource_category=rule.logsource.category,
            )

            feature_fmt = f"sigma[{self.quote_string(rule_name)}][{{}}]"
            condition = f" {self.or_token} ".join(
                self.group_expression.format(
                    expr=self.convert_post_flux_condition(feature_fmt, rule.detection, c.parse(False), state=None)
                )
                for c in rule.detection.parsed_condition
            )

            post_flux = f"{self.quote_string(rule_name)},\n{condition}"
            return Flux(
                pre=pre_flux,
                post=post_flux,
                spec=spec,
            )
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return None
            else:
                raise
        except Exception as e:  # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

    def finalize_output_flux(self, queries: list[Flux], index: int, source_type: SourceType) -> list[str]:
        source = self.last_processing_pipeline.state.get("source", {}).get(source_type)
        flux_output_source = f"{source}_flux_output_{index}" if source is not None else "--SOURCE"
        pre_flux_body = ",\n".join(q.pre.body for q in queries)
        altered_fields = ChainMap(*(q.pre.altered_fields for q in queries))
        pre_flux_from = ",\n".join([f"{key} AS {value}" for key, value in altered_fields.items()] + ["*"])

        pre_flux = f"""\
SELECT
{self.indent}*,
{self.indent}map(
{self.indent_block(pre_flux_body, 8)}
{self.indent}) as sigma
{self.indent}FROM
(
SELECT
{self.indent_block(pre_flux_from, 4)}
FROM
{self.indent}{source or "--SOURCE"}
)
"""
        post_flux_body = ",\n".join(q.post for q in queries)
        post_flux = f"""\
SELECT
{self.indent}*,
{self.indent}map_keys(
{self.indent}map_filter(
{self.indent}map(
{self.indent_block(post_flux_body, 8)}
{self.indent})
{self.indent}, (k,v) -> v = TRUE)) as sigma_final
FROM
{self.indent}{flux_output_source}
"""

        rules = "\n\n".join(self.indent_block(q.spec, 4) for q in queries if q.spec)
        spec = f"""\
rules:
{rules}
"""
        return [
            pre_flux,
            post_flux,
            spec,
        ]

    def convert_post_flux_condition(
        self,
        fmt: str,
        dets: SigmaDetections,
        cond: PostfluxConditionType,
        state: ConversionState,
    ) -> Any:
        """
        Convert query of Sigma rule into target data structure (usually query, see above).
        Dispatches to methods (see above) specialized on specific condition parse tree node objects.

        The state mainly contains the deferred list, which is used to collect query parts that are not
        directly integrated into the generated query, but added at a postponed stage of the conversion
        process after the conversion of the condition to a query is finished. This is done in the
        finalize_query method and must be implemented individually.
        """
        if isinstance(cond, ConditionOR):
            if self.decide_convert_condition_as_in_expression(cond, state):
                return self.convert_condition_as_in_expression(cond, state)
            else:
                return self.convert_post_flux_condition_or(fmt, dets, cond, state)
        elif isinstance(cond, ConditionAND):
            if self.decide_convert_condition_as_in_expression(cond, state):
                return self.convert_condition_as_in_expression(cond, state)
            else:
                return self.convert_post_flux_condition_and(fmt, dets, cond, state)
        elif isinstance(cond, ConditionNOT):
            return self.convert_post_flux_condition_not(fmt, dets, cond, state)
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.convert_condition_field_eq_val(cond, state)
        elif isinstance(cond, ConditionValueExpression):
            return self.convert_condition_val(cond, state)
        elif isinstance(cond, ConditionIdentifier):
            id = self.quote_string(self.escape_string(cond.identifier))
            return fmt.format(id)
        elif isinstance(cond, ConditionSelector):
            ids = cond.resolve_referenced_detections(dets)
            c = cond.cond_class(ids)  # type: ignore
            return self.convert_post_flux_condition(fmt, dets, c, state)
        else:  # pragma: no cover
            raise TypeError("Unexpected data type in condition parse tree: " + cond.__class__.__name__)

    def convert_post_flux_condition_group(
        self, fmt: str, dets: SigmaDetections, cond: PostfluxConditionType, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Group condition item."""
        expr = self.convert_post_flux_condition(fmt, dets, cond, state)
        if expr is None or isinstance(expr, DeferredQueryExpression):
            return expr
        return self.group_expression.format(expr=expr)

    def convert_post_flux_condition_not(
        self, fmt: str, dets: SigmaDetections, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:  # group if AND or OR condition is negated
                return (
                    self.not_token
                    + self.token_separator
                    + self.convert_post_flux_condition_group(fmt, dets, arg, state)
                )
            else:
                expr = self.convert_post_flux_condition(fmt, dets, arg, state)
                if isinstance(expr, DeferredQueryExpression):  # negate deferred expression and pass it to parent
                    return expr.negate()
                else:  # convert negated expression to string
                    return self.not_token + self.token_separator + expr
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def convert_post_flux_condition_and(
        self, fmt: str, dets: SigmaDetections, cond: ConditionAND, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            if (
                self.token_separator == self.and_token
            ):  # don't repeat the same thing triple times if separator equals and token
                joiner = self.and_token
            else:
                joiner = self.token_separator + self.and_token + self.token_separator

            return joiner.join(
                (
                    converted
                    for converted in (
                        self.convert_post_flux_condition(fmt, dets, arg, state)
                        if self.compare_precedence(cond, arg)
                        else self.convert_post_flux_condition_group(fmt, dets, arg, state)
                        for arg in cond.args
                    )
                    if converted is not None and not isinstance(converted, DeferredQueryExpression)
                )
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_post_flux_condition_or(
        self, fmt: str, dets: SigmaDetections, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        try:
            if (
                self.token_separator == self.or_token
            ):  # don't repeat the same thing triple times if separator equals or token
                joiner = self.or_token
            else:
                joiner = self.token_separator + self.or_token + self.token_separator

            return joiner.join(
                (
                    converted
                    for converted in (
                        self.convert_post_flux_condition(fmt, dets, arg, state)
                        if self.compare_precedence(cond, arg)
                        else self.convert_post_flux_condition_group(fmt, dets, arg, state)
                        for arg in cond.args
                    )
                    if converted is not None and not isinstance(converted, DeferredQueryExpression)
                )
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and not cond.value[:-1].contains_special()  # Remainder of string doesn't contains special characters
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
                value = cond.value
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = cond.value
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = cond.value
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = "{field}" + self.eq_token + "{value}"
                value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )
