from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel

CORE = "core"
EXTENDED = "extended"

_UNSAFE_ANNOTATIONS = (Any, dict, object)


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    namespace: str
    scope: str
    description: str
    input_model: type[BaseModel]
    result_model: type[BaseModel]
    handler: Callable
    tier: str = CORE
    schema_version: str = "1"
    requires_approval: bool = False


class ToolRegistry:
    """Declared tools only. Anything the registry does not know cannot be called."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._validate(spec)
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def all(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def visible_to(self, scopes: set[str], include_extended: bool) -> list[ToolSpec]:
        visible = []
        for spec in self._tools.values():
            if spec.tier == EXTENDED and not include_extended:
                continue
            if spec.scope not in scopes and "mcp:admin" not in scopes:
                continue
            visible.append(spec)
        return visible

    def _validate(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise RegistryError(f"duplicate tool name: {spec.name}")
        if not spec.name.startswith(f"{spec.namespace}."):
            raise RegistryError(f"tool {spec.name} is outside namespace {spec.namespace}")

        access = spec.scope.rsplit(":", 1)[-1]
        if access not in {"read", "write"} or spec.scope != f"mcp:{spec.namespace}:{access}":
            raise RegistryError(f"scope {spec.scope} does not match namespace {spec.namespace}")

        if not spec.schema_version:
            raise RegistryError(f"tool {spec.name} has no schema version")
        if spec.tier not in {CORE, EXTENDED}:
            raise RegistryError(f"unknown tier: {spec.tier}")

        for model in (spec.input_model, spec.result_model):
            if not (isinstance(model, type) and issubclass(model, BaseModel)):
                raise RegistryError(f"tool {spec.name} models must be pydantic models")
            for field_name, field in model.model_fields.items():
                if field.annotation in _UNSAFE_ANNOTATIONS or field.annotation is None:
                    raise RegistryError(f"tool {spec.name}: field {field_name} has an unsafe annotation")
                if _contains_any(field.annotation):
                    raise RegistryError(f"tool {spec.name}: field {field_name} must be fully typed")


def _contains_any(annotation) -> bool:
    args = getattr(annotation, "__args__", ())
    return any(arg is Any or arg is dict for arg in args)
