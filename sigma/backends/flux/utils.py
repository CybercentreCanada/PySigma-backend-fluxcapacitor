from typing import overload

from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule


@overload
def get_first(s: str) -> str:
    ...


@overload
def get_first(s: list[str]) -> str | None:
    ...


def get_first(s):
    if isinstance(s, str):
        return s
    elif isinstance(s, list) and s and isinstance((first := s[0]), str):
        return first


def alter_nested_fields(rule: SigmaRule) -> dict[str, str]:
    """
    Replace fields with dot accessor syntax with underscore and return a mapping representing the
    updates made.

    :param rule: sigma rule to change
    :returns: dictionary of the form Foo.Bar -> Foo_Bar
    """

    def get_nested(det: SigmaDetection | SigmaDetectionItem, fields: dict[str, str] | None = None) -> dict[str, str]:
        if fields is None:
            fields = {}
        if isinstance(det, SigmaDetectionItem):
            if det.field is not None and "." in det.field:
                normalized = det.field.replace(".", "_")
                fields[det.field] = normalized
                det.field = normalized
        elif isinstance(det, SigmaDetection):
            for d in det.detection_items:
                fields.update(get_nested(d))
        return fields

    mapping = {}
    for det in rule.detection.detections.values():
        for item in det.detection_items:
            mapping.update(get_nested(item))

    return mapping
