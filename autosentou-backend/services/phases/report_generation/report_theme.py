"""
Professional CSS Theme for Penetration Testing Reports

Optimized for PDF generation via Playwright with full CSS support including:
- Flexbox-based Table of Contents with dot leaders
- Severity-based color coding for findings
- Professional typography and spacing
- Print-optimized page break rules
"""

def get_professional_theme_css() -> str:
    """
    Return professional CSS theme for penetration testing reports.

    Features:
    - Modern, clean design with professional color scheme
    - Severity-based colors (Critical=red, High=yellow, Medium=orange, Low=cyan)
    - Flexbox TOC with dot leaders
    - Responsive tables with proper word wrapping
    - Print-optimized with page break controls

    Returns:
        str: Complete CSS stylesheet as <style> tag
    """
    return """<style>
/* ===== BASE STYLES ===== */
body {
    font-family: 'Segoe UI', 'Calibri', Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
    margin: 0;
    padding: 0;
    background: #fff;
}

/* Remove top margin from first element */
body > *:first-child {
    margin-top: 0 !important;
}

/* ===== TYPOGRAPHY ===== */
h1, h2, h3, h4, h5, h6 {
    color: #1a1a1a;
    margin-top: 1.2em;
    margin-bottom: 0.6em;
    padding: 0;
    page-break-after: avoid;
    font-weight: 600;
}

h1 {
    font-size: 28pt;
    border-bottom: 3px solid #2c5aa0;
    padding-bottom: 0.4em;
    margin-top: 0;
    margin-bottom: 0.8em;
    color: #2c5aa0;
}

h2 {
    font-size: 20pt;
    border-bottom: 2px solid #4a7ac7;
    padding-bottom: 0.3em;
    margin-top: 1.5em;
    margin-bottom: 0.7em;
    color: #2c5aa0;
}

h3 {
    font-size: 16pt;
    margin-top: 1.2em;
    margin-bottom: 0.5em;
    color: #2c5aa0;
}

h4 {
    font-size: 14pt;
    margin-top: 1em;
    margin-bottom: 0.4em;
    color: #4a7ac7;
}

h5 {
    font-size: 12pt;
    margin-top: 0.8em;
    margin-bottom: 0.3em;
    color: #5a8ad7;
}

p {
    margin: 0.8em 0;
}

strong {
    font-weight: 600;
    color: #000;
}

/* ===== TABLE OF CONTENTS - FLEXBOX WITH DOT LEADERS ===== */
.toc-list {
    list-style: none;
    padding: 0;
    margin: 1.5em 0;
}

.toc-item {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 4px 0;
    line-height: 1.4;
}

.toc-title-group {
    flex-shrink: 0;
    display: flex;
    align-items: baseline;
}

.toc-numeral {
    display: inline-block;
    width: 2.5em;
    flex-shrink: 0;
    text-align: right;
    padding-right: 0.5em;
    font-weight: 600;
    color: #2c5aa0;
}

.toc-content-link {
    flex-grow: 0;
    flex-shrink: 0;
    text-decoration: none;
    color: #333;
    font-weight: 500;
}

.toc-content-link:hover {
    color: #2c5aa0;
    text-decoration: underline;
}

.toc-dots-filler {
    flex-grow: 1;
    flex-shrink: 1;
    overflow: hidden;
    white-space: nowrap;
    padding: 0 8px;
    position: relative;
    min-width: 30px;
}

.toc-dots-filler::after {
    content: '. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .';
    letter-spacing: 4px;
    color: #999;
}

.toc-page-num {
    flex-shrink: 0;
    font-weight: 600;
    margin-left: 8px;
    color: #2c5aa0;
    min-width: 2em;
    text-align: right;
}

.toc-nested-list {
    margin-left: 3em;
    list-style: none;
    padding: 0;
}

.toc-nested-numeral {
    display: inline-block;
    width: 3em;
    flex-shrink: 0;
    text-align: right;
    padding-right: 0.5em;
    font-weight: 500;
    color: #4a7ac7;
}

/* ===== TABLES ===== */
table {
    border-collapse: collapse;
    width: 100%;
    margin: 1.2em 0;
    page-break-inside: avoid;
    font-size: 10pt;
}

table th {
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
    border: 1px solid #ddd;
}

table td {
    padding: 8px 12px;
    border: 1px solid #ddd;
    text-align: left;
    vertical-align: top;
}

/* Default table header style */
table thead tr {
    background-color: #2c5aa0;
    color: white;
}

table thead th {
    color: white;
}

/* Alternating row colors for readability */
table tbody tr:nth-child(even) {
    background-color: #f9f9f9;
}

table tbody tr:nth-child(odd) {
    background-color: #ffffff;
}

/* ===== SEVERITY-BASED COLORS ===== */
/* Critical Severity */
.severity-critical,
tr.severity-critical,
.bg-critical {
    background-color: #ffebee !important;
}

.text-critical {
    color: #d32f2f;
    font-weight: bold;
}

/* High Severity */
.severity-high,
tr.severity-high,
.bg-high {
    background-color: #fff9c4 !important;
}

.text-high {
    color: #f57c00;
    font-weight: bold;
}

/* Medium Severity */
.severity-medium,
tr.severity-medium,
.bg-medium {
    background-color: #ffe0b2 !important;
}

.text-medium {
    color: #ef6c00;
    font-weight: bold;
}

/* Low Severity */
.severity-low,
tr.severity-low,
.bg-low {
    background-color: #e0f7fa !important;
}

.text-low {
    color: #00838f;
    font-weight: bold;
}

/* ===== CODE BLOCKS ===== */
code {
    background-color: #f5f5f5;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 9.5pt;
    color: #c7254e;
    border: 1px solid #e1e1e8;
}

pre {
    background-color: #f8f8f8;
    border: 1px solid #ddd;
    border-left: 4px solid #2c5aa0;
    border-radius: 4px;
    padding: 14px;
    overflow-x: auto;
    page-break-inside: avoid;
    margin: 1em 0;
}

pre code {
    background-color: transparent;
    padding: 0;
    border: none;
    color: #333;
}

/* ===== LISTS ===== */
ul, ol {
    margin: 1em 0;
    padding-left: 2.5em;
}

li {
    margin: 0.5em 0;
}

ul ul, ol ul, ul ol, ol ol {
    margin: 0.3em 0;
}

/* ===== LINKS ===== */
a {
    color: #2c5aa0;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
    color: #1a3a6e;
}

/* ===== BLOCKQUOTES ===== */
blockquote {
    border-left: 4px solid #2c5aa0;
    margin: 1.2em 0;
    padding-left: 1.2em;
    color: #555;
    font-style: italic;
}

/* ===== HORIZONTAL RULES ===== */
hr {
    border: none;
    border-top: 2px solid #ddd;
    margin: 2em 0;
}

/* ===== IMAGES ===== */
img {
    max-width: 100%;
    height: auto;
    display: block;
    margin: 1.2em auto;
    border: 1px solid #ddd;
    border-radius: 4px;
    page-break-inside: avoid;
}

/* ===== PAGE BREAK UTILITIES ===== */
.page-break {
    page-break-after: always;
}

.page-break-before {
    page-break-before: always;
}

.no-break,
.avoid-break {
    page-break-inside: avoid;
}

/* Keep section headings with following content */
h2, h3, h4 {
    page-break-after: avoid;
}

/* Prevent orphans and widows */
p, li {
    orphans: 3;
    widows: 3;
}

/* ===== CONFIDENTIALITY NOTICE ===== */
.confidentiality-notice {
    border: 2px solid #d32f2f;
    background-color: #ffebee;
    padding: 1.5em;
    margin: 1.5em 0;
    border-radius: 4px;
    page-break-inside: avoid;
}

.confidentiality-notice h2 {
    color: #d32f2f;
    margin-top: 0;
    border-bottom: none;
}

/* ===== FINDING CARDS ===== */
.finding-card {
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 1.2em;
    margin: 1.5em 0;
    background-color: #fafafa;
    page-break-inside: avoid;
}

.finding-card h4 {
    margin-top: 0;
    color: #2c5aa0;
}

.finding-card .finding-id {
    color: #666;
    font-family: 'Consolas', monospace;
    font-size: 9pt;
}

/* ===== BADGES ===== */
.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 9pt;
    font-weight: 600;
    margin: 0 4px;
}

.badge-critical {
    background-color: #d32f2f;
    color: white;
}

.badge-high {
    background-color: #f57c00;
    color: white;
}

.badge-medium {
    background-color: #ffa726;
    color: white;
}

.badge-low {
    background-color: #00acc1;
    color: white;
}

/* ===== PAGE LAYOUT FOR PDF ===== */
@page {
    size: A4;
    margin: 2.5cm 2cm 3cm 2cm;

    @bottom-right {
        content: "Page " counter(page);
        font-size: 9pt;
        color: #666;
        font-family: 'Segoe UI', Arial, sans-serif;
    }

    @bottom-center {
        content: "Confidential - Penetration Testing Report";
        font-size: 8pt;
        color: #999;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
}

/* Hide footer on first page (Confidentiality Notice) */
@page :first {
    @bottom-right {
        content: none;
    }
    @bottom-center {
        content: none;
    }
}

/* ===== PRINT-SPECIFIC ADJUSTMENTS ===== */
@media print {
    body {
        print-color-adjust: exact;
        -webkit-print-color-adjust: exact;
        color-adjust: exact;
    }

    /* Ensure colors print correctly */
    table thead tr,
    .severity-critical,
    .severity-high,
    .severity-medium,
    .severity-low,
    .badge-critical,
    .badge-high,
    .badge-medium,
    .badge-low {
        print-color-adjust: exact;
        -webkit-print-color-adjust: exact;
    }

    /* Prevent page breaks in inappropriate places */
    h2, h3, h4, h5, h6 {
        page-break-after: avoid;
    }

    table, pre, blockquote, .finding-card {
        page-break-inside: avoid;
    }
}

/* ===== RESPONSIVE TABLE WORD WRAPPING ===== */
table td {
    word-wrap: break-word;
    overflow-wrap: break-word;
    word-break: break-word;
}

/* Evidence columns - force wrap long URLs/code */
table td.evidence,
table td.url,
table td.path {
    word-break: break-all;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt;
}

/* ===== COLUMN WIDTH HELPERS ===== */
.col-narrow {
    width: 10%;
}

.col-small {
    width: 15%;
}

.col-medium {
    width: 25%;
}

.col-large {
    width: 35%;
}

.col-wide {
    width: 50%;
}
</style>"""


def get_minimal_black_white_theme() -> str:
    """
    Return minimal black and white theme for simple reports.

    Returns:
        str: Complete CSS stylesheet as <style> tag
    """
    return """<style>
body {
    font-family: Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #000;
    margin: 0;
    padding: 0;
}

h1 { font-size: 24pt; border-bottom: 2px solid #000; padding-bottom: 0.3em; }
h2 { font-size: 18pt; border-bottom: 1px solid #000; padding-bottom: 0.2em; }
h3 { font-size: 14pt; }
h4 { font-size: 12pt; }

table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
}

table th, table td {
    border: 1px solid #000;
    padding: 8px;
    text-align: left;
}

table thead {
    background-color: #000;
    color: #fff;
}

code {
    font-family: 'Courier New', monospace;
    font-size: 10pt;
}

.page-break {
    page-break-after: always;
}

@media print {
    body { print-color-adjust: exact; }
}
</style>"""
