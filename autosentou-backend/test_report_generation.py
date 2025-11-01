"""
Test Report Generation

Tests the improved report generation with PDF and DOCX conversion.
"""

import sys
import os
from database import SessionLocal
from models import Job, Phase
from services.phases.report_generation.report_generator import run_report_generation_phase


def get_latest_job():
    """Get the most recent job from the database."""
    db = SessionLocal()
    try:
        job = db.query(Job).order_by(Job.created_at.desc()).first()
        return job
    finally:
        db.close()


def collect_phases_data(job_id: str):
    """Collect all phase data for a job."""
    db = SessionLocal()
    try:
        phases = db.query(Phase).filter(Phase.job_id == job_id).all()

        phases_data = {}
        for phase in phases:
            phase_name = phase.phase_name.lower().replace(' ', '_')
            phases_data[phase_name] = phase.data or {}

        return phases_data
    finally:
        db.close()


def test_report_generation():
    """Test report generation on the most recent job."""
    print("="*60)
    print("TESTING REPORT GENERATION")
    print("="*60)

    # Get latest job
    print("\n→ Fetching latest job from database...")
    job = get_latest_job()

    if not job:
        print("✗ No jobs found in database!")
        print("\nPlease run a scan first, then test report generation.")
        return False

    print(f"✓ Found job: {job.id}")
    print(f"  Target: {job.target}")
    print(f"  Status: {job.status}")
    print(f"  Created: {job.created_at}")

    # Collect phase data
    print("\n→ Collecting phase data...")
    phases_data = collect_phases_data(job.id)

    print(f"✓ Found {len(phases_data)} phases:")
    for phase_name in phases_data.keys():
        print(f"  - {phase_name}")

    # Check if packages are installed
    print("\n→ Checking required packages...")
    missing_packages = []

    try:
        import weasyprint
        print("  ✓ weasyprint installed")
    except ImportError:
        print("  ✗ weasyprint NOT installed")
        missing_packages.append("weasyprint")

    try:
        import docx
        print("  ✓ python-docx installed")
    except ImportError:
        print("  ✗ python-docx NOT installed")
        missing_packages.append("python-docx")

    if missing_packages:
        print("\n⚠ Missing packages detected!")
        print(f"  Install with: pip install {' '.join(missing_packages)}")
        print("\n  Report generation will continue but PDF/DOCX may fail.")
        response = input("\n  Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return False

    # Run report generation
    print("\n→ Running report generation...")
    db = SessionLocal()
    try:
        phase = run_report_generation_phase(db, job, phases_data)

        if phase and phase.status == "success":
            print("\n✓ Report generation completed successfully!")

            # Show generated files
            report_dir = f"reports/{job.id}"
            print(f"\nGenerated files in {report_dir}:")

            if os.path.exists(report_dir):
                files = os.listdir(report_dir)
                for file in sorted(files):
                    file_path = os.path.join(report_dir, file)
                    if os.path.isfile(file_path):
                        size = os.path.getsize(file_path)
                        print(f"  - {file} ({size:,} bytes)")

            return True
        else:
            print("\n✗ Report generation failed!")
            if phase and phase.data:
                error = phase.data.get('error', 'Unknown error')
                print(f"  Error: {error}")
            return False

    except Exception as e:
        print(f"\n✗ Report generation failed with exception!")
        print(f"  Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("IMPROVED REPORT GENERATION TEST")
    print("="*60)
    print("\nThis script will test the improved report generation including:")
    print("  • Network Services section with detailed port/service tables")
    print("  • Enhanced Information Gathering with OS detection")
    print("  • PDF conversion (requires weasyprint)")
    print("  • DOCX conversion (requires python-docx)")
    print("\n" + "="*60)

    success = test_report_generation()

    if success:
        print("\n" + "="*60)
        print("✓ TEST PASSED")
        print("="*60)
        sys.exit(0)
    else:
        print("\n" + "="*60)
        print("✗ TEST FAILED")
        print("="*60)
        sys.exit(1)
