from ..requirements_spec import RiskScorer
from loguru import logger

class PackageRiskScorer(RiskScorer):
    """
    CVSS 점수, 도달 가능성(Reachability), 권한 수준을 결합하여
    패키지의 최종 위험 점수를 계산하는 구현체.
    """

    # 도달 가능성 수준별 가중치
    REACHABILITY_WEIGHTS = {
        "NOT_LOADED": 0.1,    # 메모리에 로드되지 않음 (위험 매우 낮음)
        "LOADED": 0.5,         # 로드되었으나 실행 경로 확인 불가
        "EXECUTABLE": 0.8,     # 실행 권한이 있는 영역에 로드됨
        "REACHABLE": 1.0       # 취약 함수 심볼 존재 확인됨
    }

    def calculate_score(self, vuln_score: float, reachability: str, privilege: bool) -> float:
        """
        Score = CVSS * Reachability_Weight * Priv_Multiplier
        """
        # 1. 도달 가능성 가중치 결정
        weight = self.REACHABILITY_WEIGHTS.get(reachability, 0.1)

        # 2. 권한 승격 가능성 가중치 (Root/Privileged: 1.2x, Normal: 1.0x)
        priv_multiplier = 1.2 if privilege else 1.0

        # 3. 최종 점수 계산
        final_score = vuln_score * weight * priv_multiplier

        # 점수 상한선 10.0 (CVSS Max)
        final_score = min(final_score, 10.0)

        logger.debug(f"Calculating risk: CVSS({vuln_score}) * Reach({reachability}:{weight}) * Priv({priv_multiplier}) = {final_score}")

        return round(final_score, 2)
