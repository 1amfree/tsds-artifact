"""Extensible sink-semantic contracts for TSDS evidence capture."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Protocol


SINK_SEMANTICS_SCHEMA = "tsds-sink-semantics-v1"


def normalize_sink_name(value: str) -> str:
    return str(value or "").strip().split("@", 1)[0].lower()


@dataclass(frozen=True)
class SinkSemanticContract:
    plugin_id: str
    semantic_class: str
    argument_mode: str
    command_argument_index: int | None
    admissible_shell_claim: bool
    required_binding_trust: str
    rationale: str
    schema: str = SINK_SEMANTICS_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class SinkSemanticPlugin(Protocol):
    plugin_id: str

    def matches(self, normalized_name: str) -> bool: ...

    def contract(self, normalized_name: str) -> SinkSemanticContract: ...


@dataclass(frozen=True)
class NameSetPlugin:
    plugin_id: str
    names: frozenset[str]
    semantic_class: str
    argument_mode: str
    command_argument_index: int | None
    admissible_shell_claim: bool
    required_binding_trust: str
    rationale: str

    def matches(self, normalized_name: str) -> bool:
        return normalized_name in self.names

    def contract(self, normalized_name: str) -> SinkSemanticContract:
        return SinkSemanticContract(
            plugin_id=self.plugin_id,
            semantic_class=self.semantic_class,
            argument_mode=self.argument_mode,
            command_argument_index=self.command_argument_index,
            admissible_shell_claim=self.admissible_shell_claim,
            required_binding_trust=self.required_binding_trust,
            rationale=self.rationale,
        )


class SinkSemanticRegistry:
    def __init__(self, plugins: Iterable[SinkSemanticPlugin] = ()) -> None:
        self.plugins = list(plugins)

    def resolve(self, name: str) -> SinkSemanticContract:
        normalized = normalize_sink_name(name)
        for plugin in self.plugins:
            if plugin.matches(normalized):
                return plugin.contract(normalized)
        return SinkSemanticContract(
            plugin_id="unknown_wrapper",
            semantic_class="unknown_wrapper",
            argument_mode="unknown",
            command_argument_index=None,
            admissible_shell_claim=False,
            required_binding_trust="unbound",
            rationale="no verified sink semantic plugin matched the capture",
        )


DEFAULT_SINK_REGISTRY = SinkSemanticRegistry(
    (
        NameSetPlugin(
            plugin_id="shell_string",
            names=frozenset({"system", "popen"}),
            semantic_class="shell_command",
            argument_mode="cstring",
            command_argument_index=0,
            admissible_shell_claim=True,
            required_binding_trust="direct_abi_arg0",
            rationale="callee interprets its first C-string argument through a shell",
        ),
        NameSetPlugin(
            plugin_id="format_shell_wrapper",
            names=frozenset(
                {
                    "dosystemcmd",
                    "runsystemcmd",
                    "run_command",
                    "exec_cmd",
                    "doshell",
                    "twsystem",
                    "cstesystem",
                }
            ),
            semantic_class="shell_format_wrapper",
            argument_mode="format_cstring",
            command_argument_index=0,
            admissible_shell_claim=True,
            required_binding_trust="rendered_format_wrapper",
            rationale="verified wrapper renders a command C-string before shell dispatch",
        ),
        NameSetPlugin(
            plugin_id="direct_exec",
            names=frozenset({"execve", "execvp", "execl", "execlp"}),
            semantic_class="direct_exec_non_shell",
            argument_mode="argv_vector",
            command_argument_index=0,
            admissible_shell_claim=False,
            required_binding_trust="direct_abi_arg0",
            rationale="direct-exec uses an argv contract and requires a separate interpreter model",
        ),
    )
)


def sink_semantics_for_name(name: str) -> SinkSemanticContract:
    return DEFAULT_SINK_REGISTRY.resolve(name)

