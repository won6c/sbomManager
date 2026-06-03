import asyncio
import logging
from core.collector import SystemCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_risk_scoring():
    '''
    Verifies if the RiskScoringEngine correctly prioritizes high-impact/high-feasibility targets.
    '''
    collector = SystemCollector()
    # We use a small path to trigger binary probes quickly
    test_paths = ["/bin"] 
    
    print("\n[*] Starting Risk Scoring Verification Scan...")
    try:
        result = await collector.collect(test_paths)
        print("\n[+] Scan completed. Analyzing risk outcomes...")
        
        print("\n--- RISK ANALYSIS: DAEMONS ---")
        for d in result.daemons:
            risk = d.risk
            if risk:
                print(f"Port {d.port} | {d.description} | Score: {risk.score} [{risk.level}] | Impact: {risk.impact}, Feas: {risk.feasibility}")
                print(f"   Reason: {risk.reason}")
            else:
                print(f"Port {d.port} | {d.description} | Risk: None")

        print("\n--- RISK ANALYSIS: BINARIES ---")
        for b in result.binaries:
            risk = b.risk
            if risk:
                print(f"Path {b.path} | Score: {risk.score} [{risk.level}] | Impact: {risk.impact}, Feas: {risk.feasibility}")
                print(f"   Reason: {risk.reason}")
            else:
                print(f"Path {b.path} | Risk: None")

        print("\n--- OVERALL SYSTEM RISK ---")
        print(f"Final Score: {result.overall_risk_score:.2f}")
        print(f"Final Level: {result.overall_risk_level}")

    except Exception as e:
        print(f"\n[!] Risk test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_risk_scoring())
