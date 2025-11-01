"""
Markdown Utilities for Report Generation

Provides utilities for sanitizing and formatting markdown content,
especially for tables and cross-format conversion (MD/HTML/PDF/DOCX).
"""

import re
from typing import Any


def sanitize_table_cell(text: Any, max_length: int = None) -> str:
    """
    Sanitize text for use in markdown table cells.

    This function:
    1. Converts to string and handles None/empty values
    2. Escapes pipe characters that would break table formatting
    3. Removes or replaces problematic unicode characters
    4. Strips leading/trailing whitespace
    5. Optionally truncates to max_length

    Args:
        text: The text to sanitize (can be any type)
        max_length: Optional maximum length (will add '...' if truncated)

    Returns:
        Sanitized string safe for markdown table cells
    """
    # Handle None and convert to string
    if text is None or text == '':
        return ''

    text = str(text)

    # Replace pipe characters with HTML entity or alternative
    # Using \| doesn't work well in all markdown parsers, so we use unicode alternative
    text = text.replace('|', '&#124;')  # HTML entity for pipe

    # Replace other problematic characters
    text = text.replace('\n', ' ')  # Newlines break tables
    text = text.replace('\r', ' ')
    text = text.replace('\t', ' ')  # Tabs can cause issues

    # Remove or replace zero-width and control characters
    text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]', '', text)

    # Collapse multiple spaces
    text = re.sub(r'\s+', ' ', text)

    # Strip leading/trailing whitespace
    text = text.strip()

    # Truncate if needed
    if max_length and len(text) > max_length:
        text = text[:max_length - 3] + '...'

    return text


def sanitize_markdown_text(text: str) -> str:
    """
    Sanitize text for general markdown content (not in tables).

    Handles unicode characters that may not render well in PDF/DOCX.

    Args:
        text: The text to sanitize

    Returns:
        Sanitized string with problematic unicode replaced
    """
    if not text:
        return ''

    text = str(text)

    # Remove or replace problematic control characters
    text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]', '', text)

    return text


def replace_emoji_with_ascii(text: str) -> str:
    """
    Replace emoji and unicode symbols with ASCII alternatives.

    This ensures better compatibility with PDF/DOCX conversion.
    Common emoji used in security reports:
    - ⚠️ (Warning) -> [!]
    - ℹ️ (Info) -> [i]
    - ✓ (Check) -> [+]
    - ✗ (X) -> [-]
    - 🔒 (Lock) -> [*]

    Args:
        text: Text potentially containing emoji

    Returns:
        Text with emoji replaced by ASCII alternatives
    """
    if not text:
        return ''

    # Common security report emoji replacements
    emoji_map = {
        '⚠️': '[!]',
        '⚠': '[!]',
        'ℹ️': '[i]',
        'ℹ': '[i]',
        '✓': '[+]',
        '✔': '[+]',
        '✔️': '[+]',
        '✗': '[-]',
        '✘': '[-]',
        '🔒': '[*]',
        '🔓': '[*]',
        '⛔': '[X]',
        '❌': '[X]',
        '💡': '[?]',
        '📌': '[*]',
        '🚨': '[!!]',
        '🔴': '[!]',
        '🟡': '[!]',
        '🟢': '[+]',
    }

    for emoji, ascii_replacement in emoji_map.items():
        text = text.replace(emoji, ascii_replacement)

    # Remove any remaining emoji/unicode symbols using regex
    # This removes most emoji in the unicode emoji ranges
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags (iOS)
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
        "\U0001FA00-\U0001FA6F"  # Chess Symbols
        "]+",
        flags=re.UNICODE
    )
    text = emoji_pattern.sub('', text)

    return text


def create_markdown_table(headers: list, rows: list, max_cell_length: int = 100) -> str:
    """
    Create a properly formatted markdown table with sanitized content.

    Args:
        headers: List of column headers
        rows: List of row data (each row is a list of cell values)
        max_cell_length: Maximum length for cell content

    Returns:
        Formatted markdown table string
    """
    if not headers or not rows:
        return ''

    lines = []

    # Sanitize headers
    sanitized_headers = [sanitize_table_cell(h) for h in headers]

    # Header row
    lines.append('| ' + ' | '.join(sanitized_headers) + ' |')

    # Separator row
    lines.append('|' + '|'.join(['------' for _ in headers]) + '|')

    # Data rows
    for row in rows:
        # Ensure row has same number of columns as headers
        row_data = list(row)
        while len(row_data) < len(headers):
            row_data.append('')

        # Sanitize each cell
        sanitized_row = [sanitize_table_cell(cell, max_cell_length) for cell in row_data[:len(headers)]]
        lines.append('| ' + ' | '.join(sanitized_row) + ' |')

    return '\n'.join(lines)


def format_severity_badge(severity: str) -> str:
    """
    Format severity level with ASCII indicators instead of colors/emoji.

    Args:
        severity: Severity level (critical, high, medium, low)

    Returns:
        Formatted severity string with ASCII indicator
    """
    severity = str(severity).lower().strip()

    severity_map = {
        'critical': '[!!] CRITICAL',
        'high': '[!] HIGH',
        'medium': '[i] MEDIUM',
        'low': '[.] LOW',
        'info': '[i] INFO',
        'informational': '[i] INFORMATIONAL',
    }

    return severity_map.get(severity, f'[?] {severity.upper()}')


def safe_truncate(text: str, max_length: int, truncate_after_pipes: bool = False) -> str:
    """
    Safely truncate text, optionally removing content after pipe characters first.

    This is useful for nmap version strings that contain pipes and need truncation.

    Args:
        text: Text to truncate
        max_length: Maximum length
        truncate_after_pipes: If True, remove content after first pipe before truncating

    Returns:
        Truncated text
    """
    if not text:
        return ''

    text = str(text)

    # Remove content after pipes if requested
    if truncate_after_pipes and '|' in text:
        text = text.split('|')[0].strip()

    # Now sanitize remaining pipes
    text = sanitize_table_cell(text)

    # Truncate if still too long
    if len(text) > max_length:
        text = text[:max_length - 3] + '...'

    return text
