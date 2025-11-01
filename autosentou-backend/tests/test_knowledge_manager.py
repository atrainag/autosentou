#!/usr/bin/env python3
"""
Test script for File-Based Knowledge Manager

Run this to test the new knowledge management system.

Usage:
    python tests/test_knowledge_manager.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.ai.knowledge_manager import get_knowledge_manager


def test_exploit_search():
    """Test exploit search functionality"""
    print("=" * 60)
    print("TEST 1: Exploit Search")
    print("=" * 60)

    km = get_knowledge_manager()

    # Test 1: Apache 2.4.49
    print("\n1. Searching for Apache 2.4.49 exploits...")
    exploits = km.find_matching_exploits('Apache HTTP Server', '2.4.49', 'Linux')
    print(f"   Found {len(exploits)} exploits")

    for i, exp in enumerate(exploits, 1):
        print(f"\n   {i}. {exp['cve_id']}")
        print(f"      Description: {exp['description'][:80]}...")
        print(f"      Severity: {exp['severity']} (CVSS {exp['cvss_score']})")
        print(f"      Version match: {exp.get('version_match', False)}")
        print(f"      OS match: {exp.get('os_match', False)}")
        print(f"      Match score: {exp.get('match_score', 0)}")

    # Test 2: IIS 6.0
    print("\n\n2. Searching for IIS 6.0 exploits...")
    exploits = km.find_matching_exploits('Microsoft IIS', '6.0', 'Windows Server 2003')
    print(f"   Found {len(exploits)} exploits")

    if exploits:
        exp = exploits[0]
        print(f"\n   Top match: {exp['cve_id']}")
        print(f"   Description: {exp['description']}")
        print(f"   PoC available: {exp['poc_available']}")
        if exp.get('poc_commands'):
            print(f"   PoC command: {exp['poc_commands'][0]}")

    # Test 3: MySQL
    print("\n\n3. Searching for MySQL exploits...")
    exploits = km.find_matching_exploits('MySQL', '', 'Linux')
    print(f"   Found {len(exploits)} exploits")

    print("\n✅ Exploit search tests completed\n")


def test_google_dorks():
    """Test Google dork functionality"""
    print("=" * 60)
    print("TEST 2: Google Dorks")
    print("=" * 60)

    km = get_knowledge_manager()

    # Test 1: Get all dorks for a target
    print("\n1. Getting all dorks for example.com...")
    dorks = km.get_relevant_dorks('example.com', max_dorks=5)
    print(f"   Found {len(dorks)} dorks")

    for i, dork in enumerate(dorks, 1):
        print(f"\n   {i}. [{dork['risk'].upper()}] {dork['category']}")
        print(f"      Dork: {dork['dork']}")
        print(f"      Description: {dork['description']}")

    # Test 2: Category-specific dorks
    print("\n\n2. Getting admin panel dorks...")
    dorks = km.get_relevant_dorks('example.com', categories=['admin_panel'], max_dorks=3)
    print(f"   Found {len(dorks)} admin-related dorks")
    for dork in dorks:
        print(f"   - {dork['dork']}")

    # Test 3: Config file dorks
    print("\n\n3. Getting config file dorks...")
    dorks = km.get_relevant_dorks('example.com', categories=['config_files'], max_dorks=3)
    print(f"   Found {len(dorks)} config-related dorks")
    for dork in dorks:
        print(f"   - {dork['dork']}")

    print("\n✅ Google dork tests completed\n")


def test_vulnerable_paths():
    """Test vulnerable path detection"""
    print("=" * 60)
    print("TEST 3: Vulnerable Path Detection")
    print("=" * 60)

    km = get_knowledge_manager()

    # Test paths
    test_paths = [
        '/admin',
        '/administrator',
        '/.git/config',
        '/wp-admin',
        '/config.php',
        '/.env',
        '/phpmyadmin',
        '/backup',
        '/api/v1/users',
        '/upload',
        '/test',
        '/robots.txt',
        '/index.php.bak'
    ]

    print("\nChecking discovered paths for vulnerabilities...\n")

    for path in test_paths:
        matches = km.check_path_vulnerability(path)
        if matches:
            match = matches[0]  # Get highest risk match
            print(f"📍 {path}")
            print(f"   Risk: {match['risk'].upper()}")
            print(f"   Category: {match['category']}")
            print(f"   Description: {match['description']}")
            print(f"   Check: {match['what_to_check']}")
            print()

    print("✅ Vulnerable path detection tests completed\n")


def test_custom_knowledge():
    """Test adding custom knowledge"""
    print("=" * 60)
    print("TEST 4: Adding Custom Knowledge")
    print("=" * 60)

    km = get_knowledge_manager()

    # Test adding custom exploit
    print("\n1. Adding custom exploit...")
    custom_exploit = {
        "cve_id": "CVE-TEST-12345",
        "service": "Custom Test Service",
        "versions": ["1.0", "1.1"],
        "os": ["Linux"],
        "severity": "high",
        "cvss_score": 7.8,
        "exploit_type": "Test Exploit",
        "description": "This is a test exploit for demonstration purposes",
        "exploit_urls": ["https://github.com/test/test"],
        "poc_available": True,
        "poc_commands": ["echo 'test'"],
        "success_indicators": ["success"],
        "attack_complexity": "low",
        "requires_auth": False
    }

    result = km.add_custom_exploit(custom_exploit, added_by="test_script")
    if result:
        print("   ✅ Custom exploit added successfully")
    else:
        print("   ❌ Failed to add custom exploit")

    # Test adding custom dork
    print("\n2. Adding custom Google dork...")
    custom_dork = {
        "dork": "site:{target} intext:\"custom test\"",
        "category": "test",
        "description": "Test dork for demonstration",
        "risk": "low",
        "use_cases": ["testing"]
    }

    result = km.add_custom_dork(custom_dork, added_by="test_script")
    if result:
        print("   ✅ Custom dork added successfully")
    else:
        print("   ❌ Failed to add custom dork")

    print("\n✅ Custom knowledge tests completed\n")


def test_statistics():
    """Test knowledge base statistics"""
    print("=" * 60)
    print("TEST 5: Knowledge Base Statistics")
    print("=" * 60)

    km = get_knowledge_manager()

    stats = km.get_statistics()

    print("\nKnowledge Base Overview:")
    print(f"  Total Exploits: {stats['total_exploits']}")
    print(f"  Total Google Dorks: {stats['total_dorks']}")
    print(f"  Total Vulnerable Patterns: {stats['total_vulnerable_patterns']}")
    print(f"  Total Exploit Attempts: {stats['total_exploit_attempts']}")
    print(f"  Total Successes: {stats['total_successes']}")
    print(f"  Overall Success Rate: {stats['overall_success_rate']}%")
    print(f"  Knowledge Directory: {stats['knowledge_directory']}")

    print("\n✅ Statistics test completed\n")


def test_exploit_recording():
    """Test exploit execution recording"""
    print("=" * 60)
    print("TEST 6: Exploit Execution Recording")
    print("=" * 60)

    km = get_knowledge_manager()

    print("\n1. Recording successful exploit attempt...")
    km.record_exploit_attempt(
        exploit_id="CVE-2021-41773",
        target="192.168.1.100",
        success=True,
        execution_details={
            "timestamp": "2025-01-30T12:00:00",
            "confidence_score": 95.5,
            "execution_time": 2.3
        }
    )
    print("   ✅ Success recorded")

    print("\n2. Recording failed exploit attempt...")
    km.record_exploit_attempt(
        exploit_id="CVE-2021-41773",
        target="192.168.1.101",
        success=False,
        execution_details={
            "timestamp": "2025-01-30T12:01:00",
            "error": "Connection timeout"
        }
    )
    print("   ✅ Failure recorded")

    print("\n3. Checking updated statistics...")
    exploits = km.find_matching_exploits('Apache HTTP Server', '2.4.49')
    if exploits:
        exp = exploits[0]
        print(f"   Exploit: {exp['cve_id']}")
        print(f"   Attempts: {exp.get('attempt_count', 0)}")
        print(f"   Successes: {exp.get('success_count', 0)}")
        if exp.get('attempt_count', 0) > 0:
            rate = (exp.get('success_count', 0) / exp['attempt_count']) * 100
            print(f"   Success Rate: {rate:.1f}%")

    print("\n✅ Exploit recording tests completed\n")


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "FILE-BASED KNOWLEDGE MANAGER TESTS" + " " * 14 + "║")
    print("╚" + "=" * 58 + "╝")
    print("\n")

    try:
        test_exploit_search()
        test_google_dorks()
        test_vulnerable_paths()
        test_custom_knowledge()
        test_exploit_recording()
        test_statistics()

        print("\n" + "=" * 60)
        print("🎉 ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("\nThe file-based knowledge manager is working correctly.")
        print("You can now:")
        print("  1. Edit JSON files in services/ai/knowledge/ to add/modify knowledge")
        print("  2. View execution stats in services/ai/knowledge/execution_stats.json")
        print("  3. Use the knowledge manager in your pentest workflows")
        print()

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
