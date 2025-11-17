"""
Simple test for Information Gathering phase
Run with: python tests/test_info_gathering.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Job
from services.phases.info_gathering import run_info_gathering_phase


def test_info_gathering():
    """Test Information Gathering phase with a target."""
    db = SessionLocal()

    try:
        # Create test job
        job = Job(
            id="test-info-gathering-001",
            target="scanme.nmap.org",  # Safe test target
            description="Test Information Gathering",
            status="running",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        print(f"Created test job: {job.id}")
        print(f"Target: {job.target}\n")

        # Run phase
        print("Starting Information Gathering Phase...")
        phase = run_info_gathering_phase(db, job)

        # Display results
        print("\n" + "=" * 60)
        print("INFORMATION GATHERING RESULTS")
        print("=" * 60)
        print(f"Status: {phase.status}")
        print(f"Open ports: {len(phase.data.get('open_ports', []))}")
        print(f"Services detected: {len(phase.data.get('services', []))}")

        if phase.data.get('open_ports'):
            print("\nOpen Ports:")
            for port in phase.data['open_ports'][:5]:
                print(f"  - Port {port}")

        if phase.data.get('services'):
            print("\nServices:")
            for service in phase.data['services'][:5]:
                print(f"  - {service.get('service', 'Unknown')} on port {service.get('port')}")

        print("\n✅ Test completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        db.close()


if __name__ == "__main__":
    test_info_gathering()
