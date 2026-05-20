import networkx as nx
from typing import List, Any, Set
from ..requirements_spec import Package, DependencyGraphManager, PURL

class PackageDependencyGraph(DependencyGraphManager):
    """
    networkx를 이용한 패키지 의존성 그래프 구현체.
    순환 참조 감지 및 영향도 분석(Impact Chain)을 제공함.
    """
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self, packages: List[Package], max_depth: int = 10) -> nx.DiGraph:
        """
        Package 리스트를 바탕으로 방향성 그래프(DiGraph)를 구축.
        노드는 PURL 문자열, 엣지는 의존성 관계를 나타냄.
        """
        self.graph.clear()

        # 1. 모든 패키지를 노드로 추가
        for pkg in packages:
            purl_str = str(pkg.purl)
            self.graph.add_node(purl_str, package=pkg)

        # 2. 의존성 엣지 추가
        for pkg in packages:
            purl_str = str(pkg.purl)
            for dep_purl in pkg.dependencies:
                # dep_purl이 실제 패키지 리스트에 존재하는지 확인 없이 엣지 추가 (외부 의존성 허용)
                self.graph.add_edge(purl_str, dep_purl)

        # 3. 순환 참조 확인 및 처리 (경고 로그)
        try:
            cycles = list(nx.simple_cycles(self.graph))
            if cycles:
                # 실제 환경에서는 loguru를 사용해야 함
                print(f"[Warning] Circular dependencies detected: {cycles}")
        except Exception as e:
            print(f"Error detecting cycles: {e}")

        return self.graph

    def get_impact_chain(self, vulnerable_package_purl: str) -> List[str]:
        """
        취약한 패키지를 의존하고 있는 모든 상위 패키지를 추적.
        역방향 엣지를 따라 도달 가능한 모든 노드를 반환.
        """
        if vulnerable_package_purl not in self.graph:
            return []

        # reverse graph에서 도달 가능한 모든 노드를 찾으면,
        # 원본 그래프에서 해당 패키지를 의존하는 모든 상위 체인을 찾는 것과 같음.
        # nx.descendants는 주어진 노드에서 도달 가능한 모든 후손 노드를 반환함.
        # 여기서는 '의존함' 관계의 역방향이므로, 취약점을 포함한 상위 패키지들이 결과가 됨.

        # 역방향 그래프 생성
        reverse_graph = self.graph.reverse()
        impacted = nx.descendants(reverse_graph, vulnerable_package_purl)

        return list(impacted)
