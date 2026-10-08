# ADR 0001: YAML Parser Selection for Configuration and Span Mapping

## Status
Accepted

## Context
mcp-gate reads configuration files written in YAML 1.2. The tool has two requirements:
1. Parse YAML into strongly typed Rust domain structures (`#[serde(deny_unknown_fields)]`).
2. Map YAML AST nodes and keys to exact source spans (line and column numbers). This enables precise GitHub Actions workflow errors (`::error file=...,line=...::`) and accurate SARIF source locations.

The historical default crate `serde_yaml` was archived and deprecated in March 2024. Using an unmaintained parser for a security tool poses long-term maintenance and compatibility risks.

We evaluated three potential options:
- `serde_yaml`: Archived. Does not expose line numbers for AST spans during deserialization without custom forks.
- `serde_yml`: A community maintenance fork of `serde_yaml`. It fixes security bugs and keeps up with modern serde, but like `serde_yaml`, its high-level deserializer drops line numbers unless coupled with raw event streaming.
- `saphyr` (and `saphyr-parser`): A modern pure-Rust rewrite and modernization of `yaml-rust`. It retains byte and line markers for every token and mapping pair, giving us direct access to source spans for error annotations.

## Decision
We select `saphyr` (supported by `serde_json` for schema validation) as the core YAML parser and span provider for `mcp-gate`.

Configuration loading works in two stages:
1. Parse YAML events and document nodes to extract line/column spans into a span lookup map (`SpanMap`).
2. Deserialize the validated document into the strongly typed domain `Config` model.

## Consequences
- The codebase uses an actively maintained YAML parser with no unmaintained legacy dependencies.
- Precise line and column numbers are available for every policy entry and report annotation.
- `mcpg-domain` remains pure, holding only serde-compatible configuration models, while `mcpg-app` drives parser orchestration.
