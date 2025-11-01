"""
Test Converters

Test each converter individually with sample markdown content.
"""

import os
import sys

# Sample markdown content for testing
SAMPLE_MARKDOWN = """# Test Penetration Testing Report

**Target:** test.example.com

**Report Date:** 2025-10-31

---

## Table of Contents

**1. Executive Summary**
   1.1. Key Findings

**2. Vulnerability Summary**
   2.1. Master Vulnerability Table

---

## 1. Executive Summary

This is a **test report** with various formatting elements.

### Key Findings

- **Total Vulnerabilities**: 5
- **Critical Issues**: 2
- **SQL Injection**: Yes

You can visit [OWASP](https://owasp.org) for more information.

---

## 2. Vulnerability Summary

### Master Vulnerability Table

| ID | Severity | Service | Description |
|----|----------|---------|-------------|
| VULN-001 | Critical | Apache | Remote Code Execution |
| VULN-002 | High | MySQL | SQL Injection |
| VULN-003 | Medium | SSH | Weak Encryption |

### Detailed Findings

**VULN-001: Remote Code Execution**

This vulnerability allows `remote code execution` through the web server.

**Technical Risk**:
- Attackers can execute arbitrary code
- Full system compromise possible

**Remediation**:
1. Update Apache to latest version
2. Apply security patches
3. Review configuration

**References**:
- [CVE-2023-12345](https://nvd.nist.gov/vuln/detail/CVE-2023-12345)
- [Apache Security](https://httpd.apache.org/security/)

---

## 3. Code Example

Here's a sample code block:

```python
def vulnerable_function(user_input):
    # This is vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return execute_query(query)
```

---

## 4. Conclusion

This is the end of the test report.
"""


def test_html_converter():
    """Test HTML converter."""
    print("\n" + "="*60)
    print("Testing HTML Converter")
    print("="*60)

    from html_converter import convert_markdown_to_html

    try:
        html_content = convert_markdown_to_html(SAMPLE_MARKDOWN, "Test Report")

        # Save to file
        output_path = "/tmp/test_report.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"✓ HTML conversion successful!")
        print(f"  Output: {output_path}")
        print(f"  Size: {len(html_content)} bytes")

        # Check for key elements
        checks = [
            ("Contains <html>", "<html" in html_content),
            ("Contains CSS styling", "<style>" in html_content),
            ("Contains table", "<table>" in html_content),
            ("Contains code block", "<pre>" in html_content or "<code>" in html_content),
        ]

        for check_name, result in checks:
            status = "✓" if result else "✗"
            print(f"  {status} {check_name}")

        return True
    except Exception as e:
        print(f"✗ HTML conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_pdf_converter():
    """Test PDF converter."""
    print("\n" + "="*60)
    print("Testing PDF Converter")
    print("="*60)

    from pdf_converter import convert_markdown_to_pdf

    try:
        output_path = "/tmp/test_report.pdf"
        success = convert_markdown_to_pdf(SAMPLE_MARKDOWN, output_path, "Test Report")

        if success and os.path.exists(output_path):
            size = os.path.getsize(output_path)
            print(f"✓ PDF conversion successful!")
            print(f"  Output: {output_path}")
            print(f"  Size: {size:,} bytes")
            return True
        else:
            print(f"✗ PDF file not created")
            return False
    except Exception as e:
        print(f"✗ PDF conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_docx_converter():
    """Test DOCX converter."""
    print("\n" + "="*60)
    print("Testing DOCX Converter")
    print("="*60)

    from docx_converter import convert_markdown_to_docx

    try:
        output_path = "/tmp/test_report.docx"
        success = convert_markdown_to_docx(SAMPLE_MARKDOWN, output_path)

        if success and os.path.exists(output_path):
            size = os.path.getsize(output_path)
            print(f"✓ DOCX conversion successful!")
            print(f"  Output: {output_path}")
            print(f"  Size: {size:,} bytes")

            # Check if hyperlinks were added
            from docx import Document
            doc = Document(output_path)

            # Count hyperlinks
            hyperlink_count = 0
            for paragraph in doc.paragraphs:
                for elem in paragraph._element.findall('.//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}hyperlink'):
                    hyperlink_count += 1

            print(f"  ✓ Hyperlinks found: {hyperlink_count}")
            return True
        else:
            print(f"✗ DOCX file not created")
            return False
    except Exception as e:
        print(f"✗ DOCX conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all converter tests."""
    print("\n" + "="*60)
    print("CONVERTER TESTING SUITE")
    print("="*60)
    print("\nTesting individual converters with sample markdown content.")
    print("This ensures each converter works independently.\n")

    results = {
        'HTML': test_html_converter(),
        'PDF': test_pdf_converter(),
        'DOCX': test_docx_converter(),
    }

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    for converter, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{converter} Converter: {status}")

    all_passed = all(results.values())

    print("\n" + "="*60)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print("="*60)
        print("\nAll converters are working correctly!")
        print("Test outputs saved to /tmp/test_report.*")
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        print("="*60)
        print("\nPlease check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
