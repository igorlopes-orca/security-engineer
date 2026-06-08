#!/usr/bin/env python3
"""
Configuration for the Security Engineer orchestrator.

Settings are loaded from a YAML config file. The path is read from the
SECURITY_ENGINEER_CONFIG environment variable; if unset, built-in defaults apply.

Secrets (ORCA_API_TOKEN, NOTIFY_WEBHOOK_URL) stay as env vars — they are
not part of this config.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class OrcaCheckConfig:
    """Controls the post-PR Orca GitHub App check gate."""
    enabled: bool = True
    check_name: str = "orca-security-us"
    timeout_sec: int = 600
    poll_interval_sec: int = 15
    max_retries: int = 1
    on_failure: str = "retry"     # "retry" | "fail" | "skip"
    on_not_found: str = "skip"    # "skip" | "fail"


@dataclass
class Config:
    orca_check: OrcaCheckConfig = field(default_factory=OrcaCheckConfig)
    max_parallel_fixes: int = 4
    max_parallel_repos: int = 3


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, recursing into nested dicts."""
    merged = dict(base)
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_config() -> Config:
    """Load config from YAML file (if set) with defaults."""
    config_path = os.environ.get("SECURITY_ENGINEER_CONFIG")
    if not config_path or not Path(config_path).exists():
        return Config()

    try:
        import yaml
    except ImportError:
        print("[WARN] PyYAML not installed — using default config", flush=True)
        return Config()

    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[WARN] failed to read config {config_path}: {e}", flush=True)
        return Config()

    orca_raw = raw.get("orca_check", {})
    orca = OrcaCheckConfig(**{
        k: v for k, v in orca_raw.items()
        if k in OrcaCheckConfig.__dataclass_fields__
    })

    top = {
        k: v for k, v in raw.items()
        if k in Config.__dataclass_fields__ and k != "orca_check"
    }
    return Config(orca_check=orca, **top)
