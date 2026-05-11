# Relation Graph Engine

## Responsibilities
- Correlate disparate asset data into a unified attack surface graph.
- Identify high-risk attack paths.
- Compute reachability-based risk scores.

## Technical Requirements
- Use a graph-based data structure (e.g., networkx).
- Implement linking logic: `Network` $\rightarrow$ `Daemon` $\rightarrow$ `Binary` $\rightarrow$ `Package` $\rightarrow$ `CVE`.
- Implement a risk scoring engine based on reachability and severity.

## Tasks
- [ ] Define the graph schema (nodes and edges).
- [ ] Implement correlation logic for all plugin outputs.
- [ ] Implement attack path detection algorithms.
- [ ] Implement the final risk scoring heuristic.
