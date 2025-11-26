"""
Page Break Manager for Intelligent Report Pagination

Handles 14 fixed page break locations and prevents section cutoff by detecting
when content should be kept together on the same page.
"""

import re
from typing import List, Tuple, Optional
from enum import Enum


class PageBreakLocation(Enum):
    """Fixed page break locations in the report"""
    AFTER_CONFIDENTIALITY_NOTICE = "after_confidentiality_notice"
    AFTER_TOC = "after_toc"
    AFTER_RISK_SUMMARY_TABLE = "after_risk_summary_table"
    AFTER_OVERALL_RISK_LEVEL = "after_overall_risk_level"
    AFTER_TARGET_INFORMATION = "after_target_information"
    AFTER_TESTING_METHODOLOGY = "after_testing_methodology"
    AFTER_SOURCE_ATTRIBUTION = "after_source_attribution"
    AFTER_EVIDENCE_BLOCKS = "after_evidence_blocks"
    AFTER_REFERENCES_BLOCKS = "after_references_blocks"
    TECHNICAL_TEST_RESULTS_SECTION = "technical_test_results_section"
    AFTER_LOW_SEVERITY_FINDINGS = "after_low_severity_findings"
    BEFORE_GENERAL_RECOMMENDATIONS = "before_general_recommendations"
    BEFORE_CONCLUSION = "before_conclusion"
    BEFORE_APPENDIX = "before_appendix"
    AFTER_APPENDIX = "after_appendix"
    AFTER_REFERENCES_AND_STANDARDS = "after_references_and_standards"
    AFTER_FINAL_NOTE = "after_final_note"

class PageBreakManager:
    """
    Manages page break insertion and content break protection.

    Responsibilities:
    - Insert page breaks at 14 fixed locations
    - Detect sections that need break protection
    - Wrap content with avoid-break CSS classes
    - Provide page break HTML divs
    """

    def __init__(self):
        self.page_break_count = 0
        self.section_page_mapping = {}  # section_id -> page_number

    @staticmethod
    def create_page_break() -> str:
        """
        Create a page break HTML div.

        Returns:
            str: HTML div for page break
        """
        return '<div style="page-break-after: always;"></div>\n\n'

    @staticmethod
    def create_avoid_break_wrapper(content: str, css_class: str = "avoid-break") -> str:
        """
        Wrap content in a div that prevents page breaks inside.

        Args:
            content: Content to wrap
            css_class: CSS class name (default: "avoid-break")

        Returns:
            str: Wrapped content
        """
        return f'<div class="{css_class}">\n{content}\n</div>\n'

    def insert_page_break_after_pattern(self, content: str, pattern: str,
                                       break_type: PageBreakLocation) -> Tuple[str, int]:
        """
        Insert page break after first occurrence of pattern.

        Args:
            content: Markdown/HTML content
            pattern: Regex pattern to match
            break_type: Type of page break location

        Returns:
            Tuple of (modified_content, number_of_breaks_inserted)
        """
        match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
        if match:
            insert_pos = match.end()
            # Check if page break already exists
            if not content[insert_pos:insert_pos+50].strip().startswith('<div style="page-break'):
                page_break = f'\n\n{self.create_page_break()}'
                content = content[:insert_pos] + page_break + content[insert_pos:]
                self.page_break_count += 1
                return content, 1
        return content, 0

    def insert_page_break_after_all_patterns(self, content: str, pattern: str,
                                             break_type: PageBreakLocation) -> Tuple[str, int]:
        """
        Insert page break after ALL occurrences of pattern.

        Args:
            content: Markdown/HTML content
            pattern: Regex pattern to match
            break_type: Type of page break location

        Returns:
            Tuple of (modified_content, number_of_breaks_inserted)
        """
        breaks_inserted = 0
        offset = 0
        page_break = f'\n\n{self.create_page_break()}'

        for match in re.finditer(pattern, content, re.MULTILINE):
            insert_pos = match.end() + offset
            # Check if page break already exists
            check_after = content[insert_pos:insert_pos+50].strip()
            if not check_after.startswith('<div style="page-break'):
                content = content[:insert_pos] + page_break + content[insert_pos:]
                offset += len(page_break)
                breaks_inserted += 1
                self.page_break_count += 1

        return content, breaks_inserted

    def insert_page_break_before_pattern(self, content: str, pattern: str,
                                        break_type: PageBreakLocation) -> Tuple[str, int]:
        """
        Insert page break BEFORE first occurrence of pattern.

        Args:
            content: Markdown/HTML content
            pattern: Regex pattern to match
            break_type: Type of page break location

        Returns:
            Tuple of (modified_content, number_of_breaks_inserted)
        """
        match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
        if match:
            insert_pos = match.start()
            # Check if page break already exists
            check_before = content[max(0, insert_pos-60):insert_pos].strip()
            if not check_before.endswith('</div>'):
                page_break = f'{self.create_page_break()}\n'
                content = content[:insert_pos] + page_break + content[insert_pos:]
                self.page_break_count += 1
                return content, 1
        return content, 0

    def insert_page_break_with_fallback_patterns(self, content: str, patterns: List[str],
                                                 break_type: PageBreakLocation,
                                                 insert_before: bool = False) -> Tuple[str, int]:
        """
        Try multiple patterns in order and insert page break at first match.

        This is useful for dynamic content where sections may or may not exist.
        For example, Section 3 Severity Findings may have 3.4, 3.3, 3.2, or only 3.1
        depending on which severity levels have findings.

        Args:
            content: Markdown/HTML content
            patterns: List of regex patterns to try in priority order
            break_type: Type of page break location
            insert_before: If True, insert before pattern; if False, insert after

        Returns:
            Tuple of (modified_content, number_of_breaks_inserted)
        """
        for i, pattern in enumerate(patterns):
            match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
            if match:
                if insert_before:
                    insert_pos = match.start()
                    check_before = content[max(0, insert_pos-60):insert_pos].strip()
                    if not check_before.endswith('</div>'):
                        page_break = f'{self.create_page_break()}\n'
                        content = content[:insert_pos] + page_break + content[insert_pos:]
                        self.page_break_count += 1
                        return content, 1
                else:
                    insert_pos = match.end()
                    if not content[insert_pos:insert_pos+50].strip().startswith('<div style="page-break'):
                        page_break = f'\n\n{self.create_page_break()}'
                        content = content[:insert_pos] + page_break + content[insert_pos:]
                        self.page_break_count += 1
                        return content, 1

        # No patterns matched
        return content, 0

    def insert_dynamic_page_breaks_in_section(self, content: str, section_patterns: List[str],
                                              page_capacity: int = 35,
                                              always_break_after_last: bool = True,
                                              debug_label: str = "Section") -> Tuple[str, int]:
        """
        Dynamically insert page breaks between subsections based on LINE COUNT.

        This handles sections where subsections may have varying content lengths.
        For example, Section 5 Recommendations may have many findings in 5.1 (Critical)
        but few in 5.2 (High), requiring intelligent break placement.

        Algorithm:
        1. Find all subsections matching patterns
        2. Count LINES in each subsection (split by newlines)
        3. Accumulate line count and insert breaks when threshold exceeded
        4. Optionally ensure page break after last subsection

        Args:
            content: Markdown/HTML content
            section_patterns: List of regex patterns for subsections (in order)
            page_capacity: Lines per page (default: 45 lines, ~1 page on A4)
            always_break_after_last: Always insert break after last subsection (default: True)
            debug_label: Label for debug logging (default: "Section")

        Returns:
            Tuple of (modified_content, number_of_breaks_inserted)
        """
        breaks_inserted = 0
        accumulated_lines = 0
        offset = 0  # Track position shift as we insert breaks
        page_break = f'\n\n{self.create_page_break()}'

        print(f"\n   🔍 [{debug_label}] Dynamic page break analysis (LINE-BASED):")
        print(f"      Page capacity threshold: {page_capacity} lines/page")

        # Find all subsection matches with their positions and content
        subsections = []
        for pattern in section_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                matched_text = match.group(0)

                # Extract section label from pattern (e.g., "3.1", "5.2")
                section_label = "Unknown"
                if 'section3-' in pattern:
                    section_label = pattern.split('section3-')[1].split('>')[0].strip('"')
                    section_label = f"3.{section_label}"
                elif 'section5-' in pattern:
                    section_label = pattern.split('section5-')[1].split('>')[0].strip('"')
                    section_label = f"5.{section_label}"

                # Count LINES in this subsection
                line_count = matched_text.count('\n')

                subsections.append({
                    'start': match.start(),
                    'end': match.end(),
                    'line_count': line_count,
                    'char_count': len(matched_text),
                    'pattern': pattern,
                    'label': section_label,
                    'preview': matched_text[:100].replace('\n', ' ')
                })

        # Sort by position
        subsections.sort(key=lambda x: x['start'])

        if not subsections:
            print(f"      ⚠️  No subsections found matching patterns")
            return content, 0

        print(f"      Found {len(subsections)} subsection(s)")

        # Process each subsection
        for i, subsection in enumerate(subsections):
            accumulated_lines += subsection['line_count']
            is_last_subsection = (i == len(subsections) - 1)

            print(f"\n      [{i+1}/{len(subsections)}] {subsection['label']}: {subsection['line_count']} lines ({subsection['char_count']:,} chars)")
            print(f"         Accumulated: {accumulated_lines} lines")
            print(f"         Preview: {subsection['preview']}...")

            # Check if we should insert a page break
            should_break = False
            reason = ""
            if accumulated_lines >= page_capacity:
                should_break = True
                reason = f"exceeded threshold ({accumulated_lines} lines >= {page_capacity})"
            elif is_last_subsection and always_break_after_last:
                should_break = True
                reason = "last subsection (always_break_after_last=True)"

            if should_break:
                # Insert page break after this subsection
                insert_pos = subsection['end'] + offset

                # Check if break already exists
                check_after = content[insert_pos:insert_pos+50].strip()
                if not check_after.startswith('<div style="page-break'):
                    content = content[:insert_pos] + page_break + content[insert_pos:]
                    offset += len(page_break)
                    breaks_inserted += 1
                    self.page_break_count += 1
                    print(f"         ✅ INSERTED page break - {reason}")
                    print(f"            Position: {insert_pos + offset}")

                    # Reset accumulator
                    accumulated_lines = 0
                else:
                    print(f"         ⚠️  SKIPPED - page break already exists at this position")
            else:
                print(f"         ⏭️  No break inserted (accumulated {accumulated_lines} lines < {page_capacity})")

        print(f"\n      Total dynamic breaks inserted: {breaks_inserted}")
        return content, breaks_inserted

    def insert_dynamic_page_breaks_by_items(self, content: str, subsection_pattern: str,
                                            page_capacity: int = 18,
                                            debug_label: str = "Subsection") -> Tuple[str, int]:
        """
        Insert page breaks WITHIN a subsection based on individual numbered items.

        This is more granular than insert_dynamic_page_breaks_in_section - it looks
        inside subsections and tracks lines at the item level (1., 2., 3., 4., 5.).

        Use case: Section 5.2 may have 5 numbered recommendation items. If items 1-4
        fill a page, we need to insert a page break BEFORE item 5, not after the
        entire subsection.

        Algorithm:
        1. Find the subsection (e.g., 5.2 High Priority)
        2. Within subsection, find header + intro text
        3. Find all numbered items (1. **Title**\\n   - remediation...)
        4. Count lines: header + intro + accumulated items
        5. Insert page break before item when threshold exceeded

        Args:
            content: Markdown/HTML content
            subsection_pattern: Regex pattern for the subsection to process
            page_capacity: Lines per page (default: 20)
            debug_label: Label for debug logging

        Returns:
            Tuple of (modified_content, number_of_breaks_inserted)
        """
        breaks_inserted = 0
        page_break = f'\n\n{self.create_page_break()}'

        print(f"\n   🔍 [{debug_label}] Item-level dynamic page break analysis:")
        print(f"      Page capacity threshold: {page_capacity} lines/page")

        # Find the subsection
        subsection_match = re.search(subsection_pattern, content, re.MULTILINE | re.DOTALL)
        if not subsection_match:
            print(f"      ⚠️  Subsection not found with pattern")
            return content, 0

        subsection_start = subsection_match.start()
        subsection_end = subsection_match.end()
        subsection_content = subsection_match.group(0)

        print(f"      Found subsection: {subsection_content[:80].replace(chr(10), ' ')}...")
        print(f"      Total subsection length: {len(subsection_content)} chars, {subsection_content.count(chr(10))} lines")

        # Find header and intro text (everything before first numbered item)
        # Pattern: <h3>...</h3> followed by intro text, then "1. **..."
        # Captures everything up to (but not including) the first "1. **..."
        header_pattern = r'^.*?(?=\d+\.\s+\*\*)'
        header_match = re.search(header_pattern, subsection_content, re.MULTILINE | re.DOTALL)

        if not header_match:
            print(f"      ⚠️  No header/intro found before numbered items")
            return content, 0

        header_content = header_match.group(0)
        header_lines = header_content.count('\n')
        items_start_pos = header_match.end()

        print(f"      Header + intro: {header_lines} lines")

        # Find all numbered items within this subsection
        # Pattern: "1. **Title**\n   - remediation...\n\n"
        # Each item is typically 3 lines: title line, remediation line, empty line
        item_pattern = r'^\d+\.\s+\*\*.*?\*\*\s*\n\s+-\s+[^\n]*\n(?:\n|(?=\d+\.)|(?=<h))'
        items_content = subsection_content[items_start_pos:]

        items = []
        for match in re.finditer(item_pattern, items_content, re.MULTILINE | re.DOTALL):
            item_text = match.group(0)
            item_lines = item_text.count('\n')
            # Extract item number
            item_num_match = re.match(r'^(\d+)\.', item_text)
            item_num = item_num_match.group(1) if item_num_match else "?"

            items.append({
                'number': item_num,
                'start': match.start(),
                'end': match.end(),
                'line_count': item_lines,
                'text': item_text,
                'absolute_start': subsection_start + items_start_pos + match.start(),
                'absolute_end': subsection_start + items_start_pos + match.end()
            })

        if not items:
            print(f"      ⚠️  No numbered items found in subsection")
            return content, 0

        print(f"      Found {len(items)} numbered item(s)")

        # Track accumulated lines starting from header
        accumulated_lines = header_lines
        offset = 0

        # Process each item
        for i, item in enumerate(items):
            accumulated_lines += item['line_count']
            is_last_item = (i == len(items) - 1)

            print(f"\n      [Item {i+1}/{len(items)}] #{item['number']}: {item['line_count']} lines")
            print(f"         Accumulated: {accumulated_lines} lines (including header)")
            print(f"         Preview: {item['text'][:60].replace(chr(10), ' ')}...")

            # Check if we should insert page break BEFORE the next item
            if not is_last_item:
                next_item = items[i + 1]
                next_accumulated = accumulated_lines + next_item['line_count']

                if next_accumulated > page_capacity:
                    # Insert page break BEFORE next item (after current item)
                    insert_pos = item['absolute_end'] + offset

                    # Check if break already exists
                    check_after = content[insert_pos:insert_pos+50].strip()
                    if not check_after.startswith('<div style="page-break'):
                        content = content[:insert_pos] + page_break + content[insert_pos:]
                        offset += len(page_break)
                        breaks_inserted += 1
                        self.page_break_count += 1

                        print(f"         ✅ INSERTED page break before item #{next_item['number']}")
                        print(f"            Reason: next accumulated ({next_accumulated} lines) > capacity ({page_capacity})")

                        # Reset accumulator to just the header (start fresh page)
                        accumulated_lines = header_lines
                    else:
                        print(f"         ⚠️  SKIPPED - page break already exists")
                else:
                    print(f"         ⏭️  No break needed (next accumulated: {next_accumulated} <= {page_capacity})")
            else:
                print(f"         ℹ️  Last item - no break needed after")

        print(f"\n      Total item-level breaks inserted: {breaks_inserted}")
        return content, breaks_inserted

    def process_all_page_breaks(self, content: str) -> str:
        """
        Process all 14 page break locations in the content.

        Args:
            content: Complete markdown/HTML report content

        Returns:
            str: Content with all page breaks inserted
        """
        breaks_log = []

        # 1. After Confidentiality Notice
        content, count = self.insert_page_break_after_pattern(
            content,
            r'## Confidentiality Notice.*?\n(?:.*?\n){1,10}?(?=\n##|\n<div)',
            PageBreakLocation.AFTER_CONFIDENTIALITY_NOTICE
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Confidentiality Notice")

        # 2. After Table of Contents
        content, count = self.insert_page_break_after_pattern(
            content,
            r'</ul>\s*(?=\n##\s+1\.|\n<div|\n##\s+Executive)',
            PageBreakLocation.AFTER_TOC
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Table of Contents")

        # 3. After Table 1: Risk Summary 
        content, count = self.insert_page_break_after_pattern(
            content,
            r'\*\*Table 1: Risk Summary\*\*\n[\s\S]*?</table>', 
            PageBreakLocation.AFTER_RISK_SUMMARY_TABLE
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Risk Summary Table")

        # 4. After Overall Risk Level section
        content, count = self.insert_page_break_after_pattern(
            content,
            r'### ⚠️ Overall Risk Level.*\n[\s\S]*?\.\n', 
            PageBreakLocation.AFTER_OVERALL_RISK_LEVEL
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Overall Risk Level")

        # 5. After 2.2 Target Information (HTML heading version)
        content, count = self.insert_page_break_after_pattern(
            content,
            r'<h3 id="section2-2">2.2 Target Information</h3>\n[\s\S]*?Test Date.*', 
            PageBreakLocation.AFTER_TARGET_INFORMATION
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Target Information")

        # 6. After Testing Methodology
        content, count = self.insert_page_break_after_pattern(
            content,
            r'<h3 id="section2-3">2.3 Testing Methodology</h3>\n[\s\S]*?(?=####)', 
            PageBreakLocation.AFTER_TESTING_METHODOLOGY
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Testing Methodology")

        # 7. After Source Attribution
        content, count = self.insert_page_break_after_pattern(
            content,
            r'#### Vulnerability Information Sources\n[\s\S]*?5. \*\*AI-powered risk assessment\*\* using our internal vulnerability knowledge base', 
            PageBreakLocation.AFTER_SOURCE_ATTRIBUTION
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Source Attribution")

        # 8. Dynamic page breaks in Security Findings section (based on content length)
        # IMPORTANT: Run BEFORE Evidence/References breaks to measure clean content
        # Inserts breaks between severity levels when accumulated content exceeds page capacity
        # Match from heading to just before next <h2 or <h3 tag (not using lookahead to avoid early termination)
        severity_patterns = [
            r'<h3 id="section3-1">3\.1 Critical Severity Findings</h3>[\s\S]*?(?=<h[23] id="section)',
            r'<h3 id="section3-2">3\.2 High Severity Findings</h3>[\s\S]*?(?=<h[23] id="section)',
            r'<h3 id="section3-3">3\.3 Medium Severity Findings</h3>[\s\S]*?(?=<h[23] id="section)',
            r'<h3 id="section3-4">3\.4 Low Severity Findings</h3>[\s\S]*?(?=<h[23] id="section)',
        ]
        content, count = self.insert_dynamic_page_breaks_in_section(
            content,
            severity_patterns,
            page_capacity=20,  # 35 lines per page (conservative to prevent overflow)
            always_break_after_last=True,  # Ensure break after last severity level
            debug_label="Section 3 (Security Findings)"
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} dynamic page break(s) in Security Findings section")

        # 11.5. Technical Test Results Section (Currently having bug - skip for now)
        content, count = self.insert_page_break_after_pattern(
            content,
            r'<h3 id="section4-4">4.4 Authentication Security Testing</h3>\n[\s\S]*?(?=<h2 id="section5">5. Recommendations</h2>)', 
            PageBreakLocation.TECHNICAL_TEST_RESULTS_SECTION
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page breaks after References blocks")

        # 11. Dynamic page breaks in Recommendations section (ITEM-LEVEL granularity)
        # Process each subsection individually to insert breaks WITHIN subsections
        # when numbered items exceed page capacity
        print(f"\n📍 Location 11: Recommendations Section - Item-Level Dynamic Page Breaks")
        total_recommendations_breaks = 0

        # 11.1 Process Section 5.1 (Critical Priority) - item level
        content, count = self.insert_dynamic_page_breaks_by_items(
            content,
            r'<h3 id="section5-1">5\.1 Critical Priority \(Immediate Action Required\)</h3>[\s\S]*?(?=<h[23] id="section)',
            page_capacity=20,  # Conservative: accounts for PDF visual rendering overhead
            debug_label="Section 5.1 (Critical Priority)"
        )
        total_recommendations_breaks += count

        # 11.2 Process Section 5.2 (High Priority) - item level
        content, count = self.insert_dynamic_page_breaks_by_items(
            content,
            r'<h3 id="section5-2">5\.2 High Priority \(Address Within 30 Days\)</h3>[\s\S]*?(?=<h[23] id="section)',
            page_capacity=20,  # Conservative: accounts for PDF visual rendering overhead
            debug_label="Section 5.2 (High Priority)"
        )
        total_recommendations_breaks += count

        # 11.3 Process Section 5.3 (Medium Priority) - item level
        content, count = self.insert_dynamic_page_breaks_by_items(
            content,
            r'<h3 id="section5-3">5\.3 Medium Priority \(Plan for Next Security Cycle\)</h3>[\s\S]*?(?=<h[23] id="section)',
            page_capacity=18,  # Conservative: accounts for PDF visual rendering overhead
            debug_label="Section 5.3 (Medium Priority)"
        )
        total_recommendations_breaks += count

        # 11.4 Process Section 5.4 (General Security Recommendations) - item level
        content, count = self.insert_dynamic_page_breaks_by_items(
            content,
            r'<h3 id="section5-4">5\.4 General Security Recommendations</h3>[\s\S]*?(?=<h2 id="section)',
            page_capacity=18,  # Conservative: accounts for PDF visual rendering overhead
            debug_label="Section 5.4 (General Security)"
        )
        total_recommendations_breaks += count

        if total_recommendations_breaks:
            breaks_log.append(f"✓ Inserted {total_recommendations_breaks} item-level page break(s) in Recommendations section")

        # 9. After EACH Evidence block (multiple)
        # Run AFTER dynamic algorithms to avoid polluting content measurement
        content, count = self.insert_page_break_after_all_patterns(
            content,
            r'\*\*Evidence:\*\*\n[\s\S]*?```[\s\S]*?```',
            PageBreakLocation.AFTER_EVIDENCE_BLOCKS
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page breaks after Evidence blocks")

        # 10. After EACH References block (multiple) - after the "---" separator
        # Run AFTER dynamic algorithms to avoid polluting content measurement
        content, count = self.insert_page_break_after_all_patterns(
            content,
            r'\*\*References:\*\*\n[\s\S]*?http.*',
            PageBreakLocation.AFTER_REFERENCES_BLOCKS
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page breaks after References blocks")

        # 12. BEFORE Conclusion section (HTML heading version)
        content, count = self.insert_page_break_before_pattern(
            content,
            r'<h2 id="section6">6\. Conclusion</h2>',
            PageBreakLocation.BEFORE_CONCLUSION
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break before Conclusion")

        # 13. BEFORE Appendix section (HTML heading version)
        content, count = self.insert_page_break_before_pattern(
            content,
            r'<h2 id="section7">7\. Appendix</h2>',
            PageBreakLocation.BEFORE_APPENDIX
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break before Appendix")
        
        # 14. After Appendix section (HTML heading version)
        content, count = self.insert_page_break_after_pattern(
            content,
            r'<h2 id="section7">7\. Appendix</h2>\n[\s\S]*?(?=### 7.2)',
            PageBreakLocation.AFTER_APPENDIX
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Appendix")

        # 15. After  References and Standards
        content, count = self.insert_page_break_after_pattern(
            content,
            r'### 7\.3 References and Standards\n[\s\S]*?(?=### 7\.4 Evidence Archive)',
            PageBreakLocation.AFTER_REFERENCES_AND_STANDARDS
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after Appendix")

        # 16. After final note (at end of document)
        content, count = self.insert_page_break_after_pattern(
            content,
            r'### 7.4 Evidence Archive\n\n[\s\S]*?\*\*End of Report\*\*',
            PageBreakLocation.AFTER_FINAL_NOTE
        )
        if count:
            breaks_log.append(f"✓ Inserted {count} page break after final note")

        # Log summary
        if breaks_log:
            print("\n📄 Page Break Insertion Summary:")
            for log in breaks_log:
                print(f"   {log}")
            print(f"   Total page breaks: {self.page_break_count}\n")

        return content

    def detect_section_needing_protection(self, content: str) -> str:
        """
        Detect and wrap sections that should not be broken across pages.

        Wraps:
        - Heading + first paragraph pairs
        - Short tables
        - Code blocks with context
        - Finding cards

        Args:
            content: Markdown/HTML content

        Returns:
            str: Content with break protection applied
        """
        # Protect heading + paragraph pairs (h3/h4 followed by paragraph)
        pattern = r'(###+ [^\n]+\n\n[^\n#]+(?:\n[^\n#]+)?)'
        content = re.sub(
            pattern,
            lambda m: self.create_avoid_break_wrapper(m.group(1), "avoid-break"),
            content
        )

        return content

    def count_page_breaks(self, content: str) -> int:
        """
        Count existing page breaks in content.

        Args:
            content: Markdown/HTML content

        Returns:
            int: Number of page break divs found
        """
        return len(re.findall(r'<div style="page-break-after: always;"></div>', content))

    def get_page_number_for_section(self, section_id: str, base_page: int = 1) -> int:
        """
        Calculate page number for a section based on page breaks before it.

        Args:
            section_id: Section identifier
            base_page: Starting page number (default: 1)

        Returns:
            int: Calculated page number
        """
        return self.section_page_mapping.get(section_id, base_page)

    def map_sections_to_pages(self, content: str, section_ids: List[str], base_page: int = 1):
        """
        Create mapping of section IDs to page numbers.

        Args:
            content: Complete report content with page breaks
            section_ids: List of section identifiers in order
            base_page: Starting page number
        """
        page_breaks = list(re.finditer(r'<div style="page-break-after: always;"></div>', content))
        current_page = base_page

        for section_id in section_ids:
            # Find section position
            section_pattern = rf'<[^>]*id="{re.escape(section_id)}"[^>]*>'
            match = re.search(section_pattern, content)

            if match:
                section_pos = match.start()
                # Count page breaks before this section
                breaks_before = sum(1 for pb in page_breaks if pb.start() < section_pos)
                self.section_page_mapping[section_id] = base_page + breaks_before
