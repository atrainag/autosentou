"""
PDF Converter using Playwright (Chrome)

Converts HTML reports to PDF format with full CSS support including:
- Flexbox layouts
- Custom colors and backgrounds
- Modern CSS features
- Page break controls

Falls back to WeasyPrint if Playwright is unavailable.
"""

import os
from typing import Optional, Dict


def convert_html_to_pdf_playwright(html_content: str, output_path: str,
                                   custom_margins: Optional[Dict[str, str]] = None) -> bool:
    """
    Convert HTML to PDF using Playwright (Chromium).

    Provides full CSS support including flexbox, modern layouts, colors, etc.

    Args:
        html_content: HTML string to convert
        output_path: Path where PDF should be saved
        custom_margins: Optional custom margins dict (top, right, bottom, left)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("⚠ Playwright not installed. Attempting WeasyPrint fallback...")
        return convert_html_to_pdf_weasyprint(html_content, output_path)

    try:
        # Default margins
        if custom_margins is None:
            custom_margins = {
                'top': '1.5cm',
                'right': '2cm',
                'bottom': '1.5cm',
                'left': '2cm'
            }

        with sync_playwright() as p:
            # Launch Chromium browser
            browser = p.chromium.launch()
            page = browser.new_page()

            # Set HTML content
            page.set_content(html_content, wait_until='networkidle')

            # Generate PDF with proper settings
            page.pdf(
                path=output_path,
                format='A4',
                print_background=True,  # CRITICAL: Enable background colors/images
                margin=custom_margins,
                prefer_css_page_size=False,
                display_header_footer=False,
            )

            browser.close()

        print(f"✓ PDF generated successfully (Playwright): {output_path}")
        return True

    except Exception as e:
        print(f"✗ Playwright PDF conversion failed: {str(e)}")
        print("   Attempting WeasyPrint fallback...")
        return convert_html_to_pdf_weasyprint(html_content, output_path)


def convert_html_to_pdf(html_content: str, output_path: str, use_playwright: bool = True,
                        custom_margins: Optional[Dict[str, str]] = None) -> bool:
    """
    Convert HTML to PDF (main entry point).

    Uses Playwright by default for full CSS support, falls back to WeasyPrint if needed.

    Args:
        html_content: HTML string to convert
        output_path: Path where PDF should be saved
        use_playwright: Use Playwright if available (default: True)
        custom_margins: Optional custom margins

    Returns:
        bool: True if successful, False otherwise
    """
    if use_playwright:
        return convert_html_to_pdf_playwright(html_content, output_path, custom_margins)
    else:
        return convert_html_to_pdf_weasyprint(html_content, output_path)


def convert_html_to_pdf_weasyprint(html_content: str, output_path: str) -> bool:
    """
    Convert HTML content to PDF using WeasyPrint (fallback/legacy).

    Args:
        html_content: HTML string to convert
        output_path: Path where PDF should be saved

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
    except ImportError:
        print("✗ WeasyPrint not installed. Cannot convert to PDF.")
        return False

    try:
        # Create font configuration
        font_config = FontConfiguration()

        # Clean black and white CSS for professional PDF
        custom_css = CSS(string='''
            @page {
                size: A4;
                margin: 2.5cm;
                @bottom-right {
                    content: "Page " counter(page);
                    font-size: 9pt;
                    color: #000;
                }
            }

            body {
                font-family: 'DejaVu Sans', Arial, sans-serif;
                font-size: 10pt;
                line-height: 1.6;
                color: #000;
            }

            h1 {
                font-size: 24pt;
                color: #000;
                border-bottom: 3px solid #000;
                padding-bottom: 10px;
                margin-top: 0;
                page-break-after: avoid;
            }

            h2 {
                font-size: 18pt;
                color: #000;
                border-bottom: 2px solid #000;
                padding-bottom: 8px;
                margin-top: 30px;
                page-break-after: avoid;
            }

            h3 {
                font-size: 14pt;
                color: #000;
                margin-top: 20px;
                page-break-after: avoid;
            }

            h4 {
                font-size: 12pt;
                color: #000;
                margin-top: 15px;
                page-break-after: avoid;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
                font-size: 9pt;
                page-break-inside: avoid;
                table-layout: fixed;
            }

            table thead {
                background-color: #000;
                color: #fff;
                font-weight: bold;
            }

            table th {
                padding: 10px;
                text-align: left;
                border: 1px solid #000;
            }

            table td {
                padding: 8px;
                border: 1px solid #333;
                word-wrap: break-word;
                overflow-wrap: break-word;
                word-break: break-word;
                max-width: 200px;
            }

            /* Evidence column specific styling - force wrapping */
            table td:last-child,
            table td.evidence {
                word-wrap: break-word;
                overflow-wrap: break-word;
                word-break: break-all;
                white-space: pre-wrap;
                max-width: 250px;
                font-family: 'Courier New', monospace;
                font-size: 8pt;
            }

            table tbody tr:nth-child(even) {
                background-color: #f5f5f5;
            }

            code {
                background-color: #f0f0f0;
                padding: 2px 6px;
                border: 1px solid #ccc;
                font-family: 'Courier New', monospace;
                font-size: 9pt;
                color: #000;
                word-wrap: break-word;
                overflow-wrap: break-word;
                word-break: break-all;
            }

            pre {
                background-color: #f5f5f5;
                padding: 15px;
                border: 1px solid #ccc;
                border-left: 4px solid #000;
                font-size: 8pt;
                page-break-inside: avoid;
                white-space: pre-wrap;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }

            pre code {
                background-color: transparent;
                padding: 0;
                border: none;
            }

            hr {
                border: none;
                border-top: 1px solid #000;
                margin: 30px 0;
            }

            ul, ol {
                margin: 10px 0;
                padding-left: 30px;
            }

            li {
                margin: 5px 0;
            }

            a {
                color: #000;
                text-decoration: underline;
            }

            blockquote {
                border-left: 4px solid #000;
                padding-left: 15px;
                margin: 15px 0;
                color: #000;
                font-style: italic;
            }

            strong {
                font-weight: bold;
                color: #000;
            }

            /* Page breaks */
            .page-break {
                page-break-before: always;
            }

            /* Avoid breaks inside these elements */
            .avoid-break {
                page-break-inside: avoid;
            }

            /* Image styling */
            img {
                max-width: 100%;
                height: auto;
                display: block;
                margin: 15px auto;
                border: 1px solid #ccc;
                page-break-inside: avoid;
            }
        ''', font_config=font_config)

        # Convert HTML to PDF
        html_doc = HTML(string=html_content)
        html_doc.write_pdf(output_path, stylesheets=[custom_css], font_config=font_config)

        print(f"✓ PDF conversion successful: {output_path}")
        return True

    except Exception as e:
        print(f"✗ PDF conversion failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def convert_html_file_to_pdf(html_file_path: str, pdf_output_path: Optional[str] = None) -> bool:
    """
    Convert an HTML file to PDF.

    Args:
        html_file_path: Path to HTML file
        pdf_output_path: Path for PDF output (defaults to same name with .pdf extension)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not os.path.exists(html_file_path):
            print(f"✗ HTML file not found: {html_file_path}")
            return False

        # Read HTML file
        with open(html_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()

        # Determine output path
        if pdf_output_path is None:
            pdf_output_path = html_file_path.rsplit('.', 1)[0] + '.pdf'

        # Convert to PDF
        return convert_html_to_pdf(html_content, pdf_output_path)

    except Exception as e:
        print(f"✗ Failed to convert HTML file to PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def convert_markdown_to_pdf(markdown_content: str, output_path: str, title: str = "Penetration Testing Report") -> bool:
    """
    Convert markdown content directly to PDF.

    Args:
        markdown_content: Markdown string to convert
        output_path: Path where PDF should be saved
        title: Document title

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from .html_converter import convert_markdown_to_html

        # Convert markdown to HTML first
        html_content = convert_markdown_to_html(markdown_content, title)

        # Convert HTML to PDF
        return convert_html_to_pdf(html_content, output_path)
    except Exception as e:
        print(f"✗ Failed to convert markdown to PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
