"""
PDF Converter using WeasyPrint

Converts HTML reports to PDF format with proper styling.
"""

import os
from typing import Optional
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration


def convert_html_to_pdf(html_content: str, output_path: str) -> bool:
    """
    Convert HTML content to PDF using WeasyPrint.

    Args:
        html_content: HTML string to convert
        output_path: Path where PDF should be saved

    Returns:
        bool: True if successful, False otherwise
    """
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
            }

            pre {
                background-color: #f5f5f5;
                padding: 15px;
                border: 1px solid #ccc;
                border-left: 4px solid #000;
                overflow-x: auto;
                font-size: 8pt;
                page-break-inside: avoid;
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
