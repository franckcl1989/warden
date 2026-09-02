"""Strict JSON-Schema-subset validator for operation parameter schemas.

Decision (M2T4 brief §1): ``jsonschema`` is NOT a dependency and must not be
added. The 39 ``contracts/operations.json`` parameter schemas use only a small
closed subset, implemented here as a ~strict validator that is intentionally
narrow: any keyword outside the subset raises ``SchemaNotSupportedError`` so a
future contract change fails loudly at test time instead of validating loosely
(AGENTS.md: 没有定义时停止并记录待决策，不得自行猜测).

Supported keywords (exactly the vocabulary the 39 profiles use):

- ``type`` object/string/integer/boolean (root is always a closed object);
- ``properties`` + ``required`` + ``additionalProperties: false``;
- string ``enum`` / ``const``, ``minLength`` / ``maxLength``,
  ``format: uuid``;
- integer ``minimum`` / ``maximum``;
- ``allOf`` with ``if``/``then``/``else`` and ``not`` (poe.port.set:
  ``mode=cycle`` requires ``off_seconds``; ``mode!=cycle`` forbids it).

Error messages are Chinese and carry JSON paths (``$.mode``); an empty list
means the value conforms. The module is pure domain: no FastAPI/SQLAlchemy
imports (ARCHITECTURE.md §4).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_SCHEMA_KEYWORDS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "format",
        "allOf",
        "if",
        "then",
        "else",
        "not",
    }
)


class SchemaNotSupportedError(ValueError):
    """Raised when a parameter schema uses a keyword outside the closed subset."""


def _check_supported(schema: Mapping[str, Any], path: str) -> None:
    unknown = [key for key in schema if key not in _SCHEMA_KEYWORDS]
    if unknown:
        raise SchemaNotSupportedError(f"{path} 使用了未支持的 schema 关键字: {', '.join(sorted(unknown))}")


def _type_matches(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return False


def _errors(value: object, schema: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    _validate_value(value, schema, "$", errors)
    return errors


def _uuid_format_valid(value: str) -> bool:
    return UUID_PATTERN.fullmatch(value) is not None


def _validate_value(value: object, schema: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _check_supported(schema, path)
    declared = schema.get("type")
    if declared is not None and (not isinstance(declared, str) or not _type_matches(value, declared)):
        errors.append(f"{path} 类型不匹配，期望 {declared}")
        return
    const_value = schema.get("const")
    if const_value is not None and value != const_value:
        errors.append(f"{path} 必须等于 {const_value!r}")
        return
    enum_values = schema.get("enum")
    if enum_values is not None and (
        not isinstance(enum_values, (list, tuple)) or value not in enum_values
    ):
        errors.append(f"{path} 值不在允许范围内")
        return
    if isinstance(value, str):
        _validate_string(value, schema, path, errors)
    elif isinstance(value, int) and not isinstance(value, bool):
        _validate_integer(value, schema, path, errors)
    if isinstance(value, dict):
        _validate_object(value, schema, path, errors)
    for entry in schema.get("allOf") or ():
        if not isinstance(entry, dict):
            errors.append(f"{path} 的 allOf 条目必须是对象")
            continue
        entry_errors = _errors(value, entry)
        if entry_errors:
            errors.append(f"{path} 不满足条件约束")
    if "if" in schema:
        condition = schema["if"]
        if not isinstance(condition, dict):
            raise SchemaNotSupportedError(f"{path}.if 必须是对象")
        if _errors(value, condition) == []:
            then_schema = schema.get("then")
            if then_schema is not None:
                if not isinstance(then_schema, dict):
                    raise SchemaNotSupportedError(f"{path}.then 必须是对象")
                if _errors(value, then_schema):
                    errors.append(f"{path} 不满足条件约束")
        else:
            else_schema = schema.get("else")
            if else_schema is not None:
                if not isinstance(else_schema, dict):
                    raise SchemaNotSupportedError(f"{path}.else 必须是对象")
                if _errors(value, else_schema):
                    errors.append(f"{path} 不满足条件约束")
    if "not" in schema:
        forbidden = schema["not"]
        if not isinstance(forbidden, dict):
            raise SchemaNotSupportedError(f"{path}.not 必须是对象")
        if _errors(value, forbidden) == []:
            errors.append(f"{path} 违反了禁止约束")


def _validate_string(value: str, schema: Mapping[str, Any], path: str, errors: list[str]) -> None:
    min_length = schema.get("minLength")
    if isinstance(min_length, int) and len(value) < min_length:
        errors.append(f"{path} 长度小于 {min_length}")
    max_length = schema.get("maxLength")
    if isinstance(max_length, int) and len(value) > max_length:
        errors.append(f"{path} 长度超过 {max_length}")
    value_format = schema.get("format")
    if value_format is not None:
        if value_format != "uuid":
            raise SchemaNotSupportedError(f"{path} 使用了未支持的 format: {value_format}")
        if not _uuid_format_valid(value):
            errors.append(f"{path} 不是合法的 UUID")


def _validate_integer(value: int, schema: Mapping[str, Any], path: str, errors: list[str]) -> None:
    minimum = schema.get("minimum")
    if isinstance(minimum, int) and value < minimum:
        errors.append(f"{path} 小于最小值 {minimum}")
    maximum = schema.get("maximum")
    if isinstance(maximum, int) and value > maximum:
        errors.append(f"{path} 大于最大值 {maximum}")


def _validate_object(value: dict[Any, Any], schema: Mapping[str, Any], path: str, errors: list[str]) -> None:
    properties = schema.get("properties")
    if properties is not None and not isinstance(properties, Mapping):
        raise SchemaNotSupportedError(f"{path}.properties 必须是对象")
    required = schema.get("required")
    if required is not None and not isinstance(required, (list, tuple)):
        raise SchemaNotSupportedError(f"{path}.required 必须是数组")
    if isinstance(required, Sequence) and not isinstance(required, (str, bytes)):
        for key in required:
            if key not in value:
                errors.append(f"{path}.{key} 为必填项")
    declared_properties = properties if isinstance(properties, Mapping) else {}
    for key, item in value.items():
        prop_schema = declared_properties.get(key)
        if prop_schema is None:
            if schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key} 是不允许的字段")
        elif isinstance(prop_schema, Mapping):
            _validate_value(item, prop_schema, f"{path}.{key}", errors)


def validate_parameters(value: object, schema: Mapping[str, Any]) -> list[str]:
    """Validate ``value`` against one operations.json parameter schema.

    Returns human-readable Chinese errors; an empty list means the value
    conforms to the schema. Raises ``SchemaNotSupportedError`` when the schema
    uses a keyword outside the closed subset (contract drift must fail loudly).
    """
    if not isinstance(value, dict):
        return ["参数必须是对象"]
    if not isinstance(schema, Mapping):
        raise SchemaNotSupportedError("参数 schema 必须是对象")
    return _errors(value, schema)
