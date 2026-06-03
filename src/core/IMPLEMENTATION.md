# Core Module Implementation Details

## Overview
The core module provides the orchestration engine for the SBOM Manager. It is designed to be strictly decoupled from specific plugin implementations, providing a harness that manages the lifecycle of plugins and the flow of data through a processing pipeline.

## Components

## Components

### 1. Data Models (`core/models.py`)
Uses frozen dataclasses to ensure immutability of SBOM data as it passes through the pipeline.
- `Component`: Represents a software package. **Future scope includes expanded attributes: ComponentType (Package/Binary/Daemon/3P), absolute installed path, and filesystem permissions (rwx/setuid).**
- `Vulnerability`: Represents a security flaw (CVE ID, severity, description).
- `MappingResult`: Links a `Component` to its identified `Vulnerabilities`. **Future scope includes user-defined status (Open, Handled, etc.) and remediation history.**


### 2. Exception Hierarchy (`core/exceptions.py`)
Provides a structured way to handle errors across different layers:
- `SBOMManagerError` $\rightarrow$ Base
    - `PluginError` $\rightarrow$ `PluginLoadError`, `PluginValidationError`
    - `PipelineError` $\rightarrow$ `PipelineStageError`

### 3. Plugin System (`core/base.py` & `core/plugin_manager.py`)
- **BasePlugin**: An ABC that defines the required interface for all plugins.
- **PluginManager**: Handles dynamic loading using `importlib` and `inspect`. It can scan directories, instantiate plugins, and categorize them by `PluginType` (e.g., `SBOM_PARSER`, `CVE_PROVIDER`).

### 4. Pipeline Orchestrator (`core/pipeline.py`)
Implements a linear execution flow through four defined stages:
1. **PARSE**: Converting raw SBOM files to `Component` objects.
2. **ENRICH**: Adding metadata to components.
3. **MAP**: Identifying vulnerabilities for components.
4. **EXPORT**: Formatting results for the UI/API.

## Public API (`core/__init__.py`)
All primary classes and enums are exported at the package level for clean imports:
`from core import PluginManager, Pipeline, Component, ...`

## Implementation Status
- [x] Data Models
- [x] Exception Hierarchy
- [x] Base Plugin ABC
- [x] Plugin Manager
- [x] Pipeline Orchestrator
- [x] Public API Exports
