"""
HTML Converter

Converts markdown to clean, simple HTML with black and white styling.
"""

import markdown2
from typing import Optional


def convert_markdown_to_html(markdown_content: str, title: str = "Penetration Testing Report") -> str:
    """
    Convert markdown content to clean HTML with simple black and white styling.

    Args:
        markdown_content: Markdown string to convert
        title: HTML page title

    Returns:
        str: Complete HTML document
    """
    # Convert markdown to HTML
    html_body = markdown2.markdown(
        markdown_content,
        extras=['tables', 'fenced-code-blocks', 'header-ids', 'toc']
    )

    # Simple, clean HTML template with black & white styling
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
            background: #fff;
        }}

        h1 {{
            color: #000;
            border-bottom: 3px solid #000;
            padding-bottom: 10px;
            margin-top: 0;
        }}

        h2 {{
            color: #000;
            border-bottom: 2px solid #666;
            padding-bottom: 8px;
            margin-top: 40px;
        }}

        h3 {{
            color: #333;
            margin-top: 30px;
        }}

        h4 {{
            color: #555;
            margin-top: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #fff;
        }}

        table thead {{
            background: #000;
            color: #fff;
        }}

        table th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border: 1px solid #000;
        }}

        table td {{
            padding: 10px;
            border: 1px solid #ddd;
        }}

        table tbody tr:nth-child(even) {{
            background: #f9f9f9;
        }}

        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.9em;
            color: #000;
        }}

        pre {{
            background: #f4f4f4;
            padding: 15px;
            border-left: 4px solid #000;
            overflow-x: auto;
            font-size: 0.9em;
        }}

        pre code {{
            background: transparent;
            padding: 0;
        }}

        hr {{
            border: none;
            border-top: 1px solid #ddd;
            margin: 40px 0;
        }}

        ul, ol {{
            margin: 15px 0;
            padding-left: 30px;
        }}

        li {{
            margin: 8px 0;
        }}

        a {{
            color: #000;
            text-decoration: underline;
        }}

        a:hover {{
            color: #666;
        }}

        blockquote {{
            border-left: 4px solid #000;
            padding-left: 15px;
            margin: 20px 0;
            color: #666;
            font-style: italic;
        }}

        strong {{
            font-weight: 600;
            color: #000;
        }}

        .page-break {{
            page-break-after: always;
        }}

        @media print {{
            body {{
                max-width: 100%;
                padding: 0;
            }}

            h2 {{
                page-break-after: avoid;
            }}

            table {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    {html_body}
</body>
</html>"""

    return html_template
