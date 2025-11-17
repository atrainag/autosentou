"""
Simple test for Web Analysis phase
Run with: python tests/test_web_analysis.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Job
from services.phases.web_analysis import WebAnalysisPhase


def test_web_analysis():
    """Test Web Analysis phase with mock data."""

    # Create test database session
    db = SessionLocal()

    try:
        # Create a test job
        job = Job(
            id="test-web-analysis-001",
            target="http://testphp.vulnweb.com",
            description="Test Web Analysis Phase",
            status="running",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        print(f"Created test job: {job.id}")

        # Mock web enumeration data (simulate what Phase 2 would produce)
        web_enum_data = {
            "discovered_paths": [
                {
                    "url": "http://testphp.vulnweb.com/login.php",
                    "status_code": 200,
                    "risk_level": "high",
                    "pattern": "login"
                },
                {
                    "url": "http://testphp.vulnweb.com/artists.php",
                    "status_code": 200,
                    "risk_level": "medium",
                    "pattern": "dynamic_page"
                },
                {
                    "url": "http://testphp.vulnweb.com/AJAX/index.php",
                    "status_code": 200,
                    "risk_level": "medium",
                    "pattern": "api"
                },
            ]
        }

        print("\nStarting Web Analysis Phase...")
        print(f"Analyzing {len(web_enum_data['discovered_paths'])} discovered paths")

        # Initialize and run phase
        phase = WebAnalysisPhase(db, job)
        result = phase.execute(web_enum_data, max_pages=10)

        # Display results
        print("\n" + "=" * 60)
        print("WEB ANALYSIS RESULTS")
        print("=" * 60)
        print(f"Status: {result.status}")
        print(f"Total groups created: {result.data.get('total_groups', 0)}")
        print(f"Pages analyzed: {result.data.get('analyzed_pages', 0)}")
        print(f"Findings discovered: {result.data.get('total_findings', 0)}")

        # Show findings
        if result.data.get('findings'):
            print("\nFindings:")
            for idx, finding in enumerate(result.data['findings'][:5], 1):
                print(f"\n{idx}. {finding.get('vector')} at {finding.get('url')}")
                print(f"   ID: {finding.get('id')}")
                print(f"   Evidence: {finding.get('evidence', '')[:100]}...")
                if finding.get('payload'):
                    print(f"   Payloads: {finding.get('payload')[:2]}")

        print("\n✅ Test completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        db.close()


if __name__ == "__main__":
    test_web_analysis()
