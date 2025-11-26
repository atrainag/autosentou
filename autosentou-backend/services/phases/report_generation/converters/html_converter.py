"""
HTML Converter

Converts markdown (with embedded HTML/CSS) to complete HTML documents.
Supports full HTML passthrough and custom CSS themes.
"""

import markdown
from typing import Optional
from ..report_theme import get_professional_theme_css, get_minimal_black_white_theme


def convert_markdown_to_html(markdown_content: str, title: str = "Penetration Testing Report",
                             use_professional_theme: bool = True) -> str:
    """
    Convert markdown content to HTML with professional styling.

    Supports:
    - Full HTML passthrough (embedded HTML in markdown)
    - Custom CSS themes
    - Styled tables with colors
    - Flexbox TOC
    - Page break divs

    Args:
        markdown_content: Markdown string to convert (may contain HTML)
        title: HTML page title
        use_professional_theme: Use professional CSS theme (default: True)

    Returns:
        str: Complete HTML document
    """
    # Convert markdown to HTML using markdown library (supports HTML passthrough)
    html_body = markdown.markdown(
        markdown_content,
        extensions=[
            'extra',           # Tables, fenced code, etc.
            'codehilite',      # Syntax highlighting
            'tables',          # Table support
            'fenced_code',     # Fenced code blocks
            'nl2br',           # Newline to <br>
            'sane_lists',      # Better list handling
        ]
    )

    # Get CSS theme
    if use_professional_theme:
        css_theme = get_professional_theme_css()
    else:
        css_theme = get_minimal_black_white_theme()

    # Create complete HTML document
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {css_theme}
</head>
<body>
    {html_body}
</body>
</html>"""

    return html_template
