"""
Configuration management for VYASA.
Loads YAML configurations with fallback defaults.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from pydantic import BaseModel


class LLMConfig(BaseModel):
    base_url: str = "http://127.0.0.1:1234/v1"
    api_key: str = "lm-studio"
    model: str = "qwen2.5-7b-instruct-abliterated"
    temperature: float = 0.2
    max_tokens: int = 3072
    timeout_seconds: int = 60


class ReconConfig(BaseModel):
    subdomain_enumeration: bool = True
    port_scan: bool = True
    top_ports: int = 1000
    tech_detection: bool = True
    timeout_seconds: int = 180


class TestingConfig(BaseModel):
    active_probing: bool = True
    safe_mode: bool = True
    max_parallel_scans: int = 4


class ReasoningConfig(BaseModel):
    max_correlation_depth: int = 4
    enable_chain_of_thought: bool = True
    min_path_confidence: float = 0.70


class ReportingConfig(BaseModel):
    output_format: list = ["markdown", "json"]
    output_dir: str = "./reports"
    include_attack_graph_diagrams: bool = True


class AppConfig(BaseModel):
    platform_name: str = "VYASA"
    version: str = "0.1.0"
    mode: str = "authorized_audit"
    llm: LLMConfig = LLMConfig()
    recon: ReconConfig = ReconConfig()
    testing: TestingConfig = TestingConfig()
    reasoning: ReasoningConfig = ReasoningConfig()
    reporting: ReportingConfig = ReportingConfig()


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from a YAML file or use defaults."""
    if not config_path:
        default_path = Path(__file__).resolve().parent.parent.parent / "config" / "default_config.yaml"
        config_path = str(default_path)

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
            
            return AppConfig(
                platform_name=raw_data.get("platform", {}).get("name", "VYASA"),
                version=raw_data.get("platform", {}).get("version", "0.1.0"),
                mode=raw_data.get("platform", {}).get("mode", "authorized_audit"),
                llm=LLMConfig(**raw_data.get("llm", {})),
                recon=ReconConfig(**raw_data.get("recon", {})),
                testing=TestingConfig(**raw_data.get("testing", {})),
                reasoning=ReasoningConfig(**raw_data.get("reasoning", {})),
                reporting=ReportingConfig(**raw_data.get("reporting", {}))
            )
    return AppConfig()
