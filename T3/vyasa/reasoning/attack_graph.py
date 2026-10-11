"""
Attack Graph Engine for VYASA.
Represents security findings and relationships as a directed graph to model kill chains.
"""

import networkx as nx
import logging
from typing import List, Dict, Any
from vyasa.core.models import Asset, Finding, AttackPath

logger = logging.getLogger("vyasa.reasoning.graph")


class AttackGraphBuilder:
    """Constructs and queries the multi-hop attack graph for an engagement."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self, assets: List[Asset], findings: List[Finding], attack_paths: List[AttackPath]) -> nx.DiGraph:
        """Populates the directed graph with assets, vulnerabilities, and path steps."""
        self.graph.clear()

        # Add Asset Nodes
        for asset in assets:
            self.graph.add_node(
                asset.asset_id,
                node_type="asset",
                label=asset.host,
                ports=asset.open_ports
            )

        # Add Finding Nodes
        for finding in findings:
            self.graph.add_node(
                finding.finding_id,
                node_type="finding",
                label=finding.title,
                severity=finding.severity.value
            )
            # Edge from Finding -> Asset it affects
            self.graph.add_edge(finding.finding_id, finding.asset_id, relation="affects")

        # Add Attack Path Sequence Edges
        for path in attack_paths:
            prev_node = None
            for step in path.steps:
                step_node_id = f"{path.path_id}_step_{step.step_order}"
                self.graph.add_node(
                    step_node_id,
                    node_type="attack_step",
                    label=step.title,
                    technique=step.technique
                )
                if step.source_finding_id and step.source_finding_id in self.graph:
                    self.graph.add_edge(step.source_finding_id, step_node_id, relation="enables")

                if prev_node:
                    self.graph.add_edge(prev_node, step_node_id, relation="transitions_to")

                prev_node = step_node_id

        logger.info(f"Attack graph constructed: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges.")
        return self.graph

    def generate_ascii_tree(self, path: AttackPath) -> str:
        """Generates an ASCII/Unicode visual tree representing an attack trajectory."""
        lines = [f"[Attack Path] {path.title} ({path.composite_severity.value})"]
        for idx, step in enumerate(path.steps):
            connector = "└── " if idx == len(path.steps) - 1 else "├── "
            lines.append(f"  {connector}Step {step.step_order}: {step.title} [{step.technique}] -> Impact: {step.impact}")
        return "\n".join(lines)
