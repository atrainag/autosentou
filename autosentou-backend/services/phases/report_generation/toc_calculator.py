"""
Table of Contents Page Number Calculator

Calculates accurate page numbers for TOC entries based on page break locations
in the document.
"""

import re
from typing import Dict, List, Tuple, Optional


class TOCEntry:
    """Represents a single TOC entry"""

    def __init__(self, number: str, title: str, section_id: str, is_subsection: bool = False):
        """
        Initialize TOC entry.

        Args:
            number: Section number (e.g., "1", "2.1", "3.2.1")
            title: Section title
            section_id: HTML ID for linking
            is_subsection: Whether this is a subsection
        """
        self.number = number
        self.title = title
        self.section_id = section_id
        self.is_subsection = is_subsection
        self.page_number = 1  # Will be calculated

    def __repr__(self):
        return f"TOCEntry({self.number}. {self.title} → Page {self.page_number})"


class TOCCalculator:
    """
    Calculates page numbers for Table of Contents based on page breaks.

    The calculator scans the document for page breaks and section headers,
    then assigns accurate page numbers to each TOC entry.
    """

    def __init__(self, base_page: int = 1):
        """
        Initialize TOC calculator.

        Args:
            base_page: Starting page number (default: 1)
        """
        self.base_page = base_page
        self.toc_entries: List[TOCEntry] = []
        self.page_break_positions: List[int] = []

    def add_entry(self, number: str, title: str, section_id: str, is_subsection: bool = False) -> TOCEntry:
        """
        Add a TOC entry.

        Args:
            number: Section number
            title: Section title
            section_id: HTML ID
            is_subsection: Whether this is a subsection

        Returns:
            TOCEntry: Created entry
        """
        entry = TOCEntry(number, title, section_id, is_subsection)
        self.toc_entries.append(entry)
        return entry

    def scan_page_breaks(self, content: str):
        """
        Scan document for page break positions.

        Args:
            content: Complete document content with page breaks
        """
        self.page_break_positions = []
        for match in re.finditer(r'<div style="page-break-after: always;"></div>', content):
            self.page_break_positions.append(match.start())

        print(f"   📄 Found {len(self.page_break_positions)} page breaks in document")

    def calculate_page_number(self, content: str, section_id: str) -> int:
        """
        Calculate page number for a section based on page breaks before it.

        Args:
            content: Complete document content
            section_id: Section HTML ID to find

        Returns:
            int: Calculated page number
        """
        # Find section position in content
        # Try multiple patterns to find the section
        patterns = [
            rf'<[^>]*id="{re.escape(section_id)}"[^>]*>',  # HTML element with ID
            rf'##\s+{re.escape(section_id.replace("section", ""))}[\.\s]',  # Markdown heading with number
        ]

        section_pos = None
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                section_pos = match.start()
                break

        if section_pos is None:
            # If section not found, try searching by title
            return self.base_page

        # Count page breaks before this section
        breaks_before = sum(1 for pos in self.page_break_positions if pos < section_pos)

        return self.base_page + breaks_before

    def calculate_all_page_numbers(self, content: str):
        """
        Calculate page numbers for all TOC entries.

        Args:
            content: Complete document content with page breaks
        """
        # First scan for all page breaks
        self.scan_page_breaks(content)

        # Calculate page number for each entry
        for entry in self.toc_entries:
            entry.page_number = self.calculate_page_number(content, entry.section_id)

        print(f"   ✓ Calculated page numbers for {len(self.toc_entries)} TOC entries")

    def generate_styled_toc_html(self) -> str:
        """
        Generate HTML for styled Table of Contents with flexbox and dot leaders.

        Returns:
            str: HTML for TOC with page numbers
        """
        lines = []
        lines.append('## Table of Contents\n\n')
        lines.append('<ul class="toc-list">\n')

        current_parent = None

        for entry in self.toc_entries:
            if entry.is_subsection:
                # Check if we need to open a nested list
                parent_num = entry.number.rsplit('.', 1)[0]
                if current_parent != parent_num:
                    lines.append('    <ul class="toc-nested-list">\n')
                    current_parent = parent_num

                # Subsection item
                lines.append('        <li class="toc-item">\n')
                lines.append('            <div class="toc-title-group">\n')
                lines.append(f'                <span class="toc-nested-numeral">{entry.number}</span>\n')
                lines.append(f'                <a href="#{entry.section_id}" class="toc-content-link">{entry.title}</a>\n')
                lines.append('            </div>\n')
                lines.append('            <span class="toc-dots-filler"></span>\n')
                lines.append(f'            <span class="toc-page-num">{entry.page_number}</span>\n')
                lines.append('        </li>\n')

            else:
                # Close any open nested list
                if current_parent is not None:
                    lines.append('    </ul>\n')
                    current_parent = None

                # Main section item
                lines.append('    <li class="toc-item">\n')
                lines.append('        <div class="toc-title-group">\n')
                lines.append(f'            <span class="toc-numeral">{entry.number}.</span>\n')
                lines.append(f'            <a href="#{entry.section_id}" class="toc-content-link">{entry.title}</a>\n')
                lines.append('        </div>\n')
                lines.append('        <span class="toc-dots-filler"></span>\n')
                lines.append(f'        <span class="toc-page-num">{entry.page_number}</span>\n')
                lines.append('    </li>\n')

        # Close any remaining nested list
        if current_parent is not None:
            lines.append('    </ul>\n')

        lines.append('</ul>\n')

        return ''.join(lines)

    def generate_simple_toc_markdown(self) -> str:
        """
        Generate simple markdown TOC (fallback).

        Returns:
            str: Markdown for TOC
        """
        lines = []
        lines.append('## Table of Contents\n\n')

        for entry in self.toc_entries:
            if entry.is_subsection:
                indent = '   '
                lines.append(f"{indent}{entry.number}. {entry.title} ....... Page {entry.page_number}\n")
            else:
                lines.append(f"**{entry.number}. {entry.title}** ....... Page {entry.page_number}\n")

        lines.append('\n')
        return ''.join(lines)

    def get_toc_stats(self) -> Dict[str, int]:
        """
        Get statistics about the TOC.

        Returns:
            Dict with stats: total_entries, main_sections, subsections, total_pages
        """
        main_sections = sum(1 for e in self.toc_entries if not e.is_subsection)
        subsections = sum(1 for e in self.toc_entries if e.is_subsection)
        max_page = max((e.page_number for e in self.toc_entries), default=self.base_page)

        return {
            'total_entries': len(self.toc_entries),
            'main_sections': main_sections,
            'subsections': subsections,
            'total_pages': max_page,
        }

    def print_toc_summary(self):
        """Print summary of TOC entries and page numbers."""
        stats = self.get_toc_stats()
        print(f"\n📑 Table of Contents Summary:")
        print(f"   Total entries: {stats['total_entries']}")
        print(f"   Main sections: {stats['main_sections']}")
        print(f"   Subsections: {stats['subsections']}")
        print(f"   Estimated pages: {stats['total_pages']}")
        print(f"\n   TOC Entries:")
        for entry in self.toc_entries:
            indent = "      " if entry.is_subsection else "   "
            print(f"{indent}{entry.number}. {entry.title} → Page {entry.page_number}")
