"""
Simple test for Web Enumeration phase
Run with: python tests/test_web_enumeration.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Job
from services.phases.web_enumeration import run_web_enumeration_phase


def test_web_enumeration():
    """Test Web Enumeration phase."""
    db = SessionLocal()

    try:
        # Create test job
        job = Job(
            id="test-web-enum-001",
            target="http://testphp.vulnweb.com",
            description="Test Web Enumeration",
            status="running",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        print(f"Created test job: {job.id}")
        print(f"Target: {job.target}\n")

        # Mock info gathering data
        info_data = {
            "web_ports": [80, 443],
            "open_ports": [80],
            "services": [
                {"port": 80, "service": "http", "version": "Apache 2.4"}
            ]
        }

        # Run phase
        print("Starting Web Enumeration Phase...")
        phase = run_web_enumeration_phase(db, job, info_data, custom_wordlist=None)

        # Display results
        print("\n" + "=" * 60)
        print("WEB ENUMERATION RESULTS")
        print("=" * 60)
        print(f"Status: {phase.status}")
        print(f"Discovered paths: {len(phase.data.get('discovered_paths', []))}")

        if phase.data.get('discovered_paths'):
            print("\nHigh-Risk Paths:")
            for path in phase.data['discovered_paths'][:10]:
                if path.get('risk_level') in ['critical', 'high']:
                    print(f"  - {path.get('url')} ({path.get('risk_level')})")

        print("\n✅ Test completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        db.close()


if __name__ == "__main__":
    test_web_enumeration()
