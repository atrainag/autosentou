"""
Simple test for Authentication Testing phase
Run with: python tests/test_authentication_testing.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Job
from services.phases.authentication_testing import run_authentication_testing_phase


def test_authentication_testing():
    """Test Authentication Testing phase."""
    db = SessionLocal()

    try:
        # Create test job
        job = Job(
            id="test-auth-001",
            target="http://testphp.vulnweb.com",
            description="Test Authentication Testing",
            status="running",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        print(f"Created test job: {job.id}")
        print(f"Target: {job.target}\n")

        # Mock web enumeration data
        web_enum_data = {
            "login_pages": [
                {"url": "http://testphp.vulnweb.com/login.php", "risk_level": "high"}
            ],
            "discovered_paths": []
        }

        # Run phase
        print("Starting Authentication Testing Phase...")
        phase = run_authentication_testing_phase(db, job, web_enum_data)

        # Display results
        print("\n" + "=" * 60)
        print("AUTHENTICATION TESTING RESULTS")
        print("=" * 60)
        print(f"Status: {phase.status}")
        print(f"Login pages tested: {len(phase.data.get('tested_login_pages', []))}")

        if phase.data.get('tested_login_pages'):
            print("\nResults:")
            for result in phase.data['tested_login_pages']:
                print(f"  - {result.get('url')}")
                print(f"    Username enumeration: {result.get('username_enumeration_possible', False)}")

        print("\n✅ Test completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        db.close()


if __name__ == "__main__":
    test_authentication_testing()
