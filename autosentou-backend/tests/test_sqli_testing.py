"""
Simple test for SQL Injection Testing phase
Run with: python tests/test_sqli_testing.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Job
from services.phases.sqli_testing import run_sqli_testing_phase


def test_sqli_testing():
    """Test SQL Injection Testing phase."""
    db = SessionLocal()

    try:
        # Create test job
        job = Job(
            id="test-sqli-001",
            target="http://testphp.vulnweb.com",
            description="Test SQLi Testing",
            status="running",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        print(f"Created test job: {job.id}")
        print(f"Target: {job.target}\n")

        # Mock web enumeration data
        web_enum_data = {
            "discovered_paths": [
                {"url": "http://testphp.vulnweb.com/artists.php?artist=1", "risk_level": "medium"},
                {"url": "http://testphp.vulnweb.com/login.php", "risk_level": "high"}
            ]
        }

        # Run phase
        print("Starting SQLi Testing Phase...")
        phase = run_sqli_testing_phase(db, job, web_enum_data)

        # Display results
        print("\n" + "=" * 60)
        print("SQLI TESTING RESULTS")
        print("=" * 60)
        print(f"Status: {phase.status}")
        print(f"Endpoints tested: {phase.data.get('endpoints_tested', 0)}")
        print(f"Vulnerable endpoints: {phase.data.get('vulnerable_endpoints', 0)}")

        if phase.data.get('sqli_results'):
            print("\nResults:")
            for result in phase.data['sqli_results'][:3]:
                print(f"  - {result.get('url')}: {result.get('status', 'unknown')}")

        print("\n✅ Test completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        db.close()


if __name__ == "__main__":
    test_sqli_testing()
