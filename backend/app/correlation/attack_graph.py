import networkx as nx
from typing import Any

from app.core.events import SecurityEvent, DetectionAlert


class AttackGraphGenerator:
    @staticmethod
    def generate_graph(alerts: list[DetectionAlert], events: list[SecurityEvent]) -> dict[str, list[dict[str, Any]]]:
        """
        Builds a directed graph using networkx of the incident entities and actions.
        Returns a JSON-serializable node/edge schema.
        """
        G = nx.DiGraph()

        # Helper to safely add nodes with types
        def add_node(name: str, node_type: str):
            if name:
                G.add_node(name, type=node_type, label=name)

        # 1. Process all events to build entity relationships
        for e in events:
            # Host node
            add_node(e.host, "host")

            # User node
            if e.user:
                add_node(e.user, "user")
                G.add_edge(e.user, e.host, relation="logged_into")

            # Network connections
            if e.source_ip:
                add_node(e.source_ip, "ip")
                if e.user:
                    G.add_edge(e.source_ip, e.user, relation="authenticated_from")

            if e.destination_ip:
                add_node(e.destination_ip, "ip")
                if e.process_name:
                    add_node(e.process_name, "process")
                    G.add_edge(e.process_name, e.destination_ip, relation="communicated_with")
                elif e.source_ip:
                    G.add_edge(e.source_ip, e.destination_ip, relation="connected_to")

            # Process relationships
            if e.process_name:
                add_node(e.process_name, "process")
                if e.user:
                    G.add_edge(e.user, e.process_name, relation="executed")
                
                if e.parent_process:
                    add_node(e.parent_process, "process")
                    G.add_edge(e.parent_process, e.process_name, relation="spawned")

            # File/service operations
            if e.event_type.value in ("FILE_CREATED", "FILE_MODIFIED", "FILE_ACCESS"):
                file_path = e.message.split("file: ", 1)[-1] if "file:" in e.message else "file"
                add_node(file_path, "file")
                if e.process_name:
                    G.add_edge(e.process_name, file_path, relation="accessed")

        # 2. Add alerts as nodes and connect to their subject users/hosts
        for a in alerts:
            alert_node = f"Alert: {a.rule_name}"
            G.add_node(alert_node, type="alert", label=a.rule_name, severity=a.risk_contribution)
            
            if a.user:
                add_node(a.user, "user")
                G.add_edge(alert_node, a.user, relation="implicates")
            if a.host:
                add_node(a.host, "host")
                G.add_edge(alert_node, a.host, relation="targets")

        # Serialize networkx graph to standard node/edge dictionary
        nodes = []
        for n, data in G.nodes(data=True):
            nodes.append({
                "id": n,
                "label": data.get("label", n),
                "type": data.get("type", "unknown"),
                "severity": data.get("severity", 0)
            })

        edges = []
        for u, v, data in G.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "relation": data.get("relation", "relates_to")
            })

        return {"nodes": nodes, "edges": edges}


attack_graph_generator = AttackGraphGenerator()
