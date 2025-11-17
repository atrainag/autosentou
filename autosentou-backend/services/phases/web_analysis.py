"""
services/phases/web_analysis.py
Deep Web Analysis Phase using Playwright + LLM for intelligent vulnerability detection
"""
import os
import json
import hashlib
import logging
import asyncio
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, Page
from models import Phase, Job, Finding
from services.ai.ai_service import get_ai_service
from services.utils.output_manager import get_output_manager

logger = logging.getLogger(__name__)


class ResponseGroup:
    """Groups similar responses for pruning."""

    def __init__(self, status_code: int, content_length: int):
        self.status_code = status_code
        self.content_length = content_length
        self.urls: List[str] = []
        self.representative_url: Optional[str] = None

    def add_url(self, url: str):
        """Add URL to this group."""
        self.urls.append(url)
        # Representative is the shortest/simplest URL
        if not self.representative_url or len(url) < len(self.representative_url):
            self.representative_url = url

    def matches(self, status_code: int, content_length: int, tolerance: float = 0.1) -> bool:
        """Check if response matches this group (±10% size tolerance)."""
        if status_code != self.status_code:
            return False

        # Allow ±10% size variation
        min_size = self.content_length * (1 - tolerance)
        max_size = self.content_length * (1 + tolerance)

        return min_size <= content_length <= max_size


class WebAnalysisPhase:
    """
    Deep web analysis using Playwright and LLM.

    Workflow:
    1. Take high-priority paths from Web Enumeration
    2. Crawl each path with Playwright (render JavaScript)
    3. Group similar responses by status code + content size
    4. Analyze representative pages with LLM
    5. Extract structured findings (vector, evidence, payload, etc.)
    6. Save findings to database
    """

    def __init__(self, db_session, job: Job):
        self.db = db_session
        self.job = job
        self.output_dir = f"reports/{job.id}/web_analysis"
        os.makedirs(self.output_dir, exist_ok=True)

        # Get AI service
        self.ai_service = get_ai_service()

        # Tracking
        self.response_groups: List[ResponseGroup] = []
        self.analyzed_findings: List[Dict[str, Any]] = []
        self.finding_ids_seen: Set[str] = set()

        logger.info(f"WebAnalysisPhase initialized for job {job.id}")

    def execute(self, web_enum_data: Dict[str, Any], max_pages: int = 100) -> Phase:
        """
        Execute web analysis phase.

        Args:
            web_enum_data: Data from web enumeration phase
            max_pages: Maximum pages to analyze (default: 100)

        Returns:
            Phase object with results
        """
        phase = Phase(
            job_id=self.job.id,
            phase_name="Web Analysis",
            data={},
            log_path=None,
            status="ongoing",
        )
        self.db.add(phase)
        self.db.commit()
        self.db.refresh(phase)

        try:
            logger.info("=" * 80)
            logger.info(f"[Job {self.job.id}] STARTING WEB ANALYSIS PHASE")
            logger.info("=" * 80)

            # Extract high-priority paths from web enumeration
            high_priority_paths = self._extract_high_priority_paths(web_enum_data, max_pages)

            if not high_priority_paths:
                logger.warning(f"[Job {self.job.id}] No high-priority paths found")
                phase.status = "completed"
                phase.data = {"error": "No paths to analyze"}
                self.db.commit()
                return phase

            logger.info(f"[Job {self.job.id}] Found {len(high_priority_paths)} high-priority paths")

            # Run async analysis
            analysis_results = asyncio.run(self._analyze_paths_async(high_priority_paths))

            # Save results to phase
            phase.data = {
                "total_paths_discovered": len(web_enum_data.get("discovered_paths", [])),
                "high_priority_paths": len(high_priority_paths),
                "total_groups": len(self.response_groups),
                "analyzed_pages": len(analysis_results),
                "total_findings": len(self.analyzed_findings),
                "findings": self.analyzed_findings,
            }
            phase.status = "completed"
            self.db.commit()

            # Extract findings to DB
            self._save_findings_to_db(phase)

            logger.info("=" * 80)
            logger.info(f"[Job {self.job.id}] WEB ANALYSIS PHASE COMPLETED")
            logger.info(f"  Analyzed: {len(analysis_results)} pages")
            logger.info(f"  Findings: {len(self.analyzed_findings)}")
            logger.info("=" * 80)

            return phase

        except Exception as e:
            logger.error(f"Web analysis phase failed: {e}")
            import traceback
            traceback.print_exc()

            phase.status = "failed"
            phase.data = {"error": str(e)}
            self.db.commit()
            return phase

    def _extract_high_priority_paths(
        self,
        web_enum_data: Dict[str, Any],
        max_paths: int
    ) -> List[Dict[str, Any]]:
        """Extract high-priority paths from web enumeration data."""
        discovered_paths = web_enum_data.get("discovered_paths", [])

        if not discovered_paths:
            return []

        # Sort by risk level: critical > high > medium > low
        risk_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        sorted_paths = sorted(
            discovered_paths,
            key=lambda p: (
                risk_priority.get(p.get("risk_level", "info"), 5),
                -p.get("status_code", 0)  # Prefer accessible pages (200, 403, 401)
            )
        )

        # Take top N paths
        return sorted_paths[:max_paths]

    async def _analyze_paths_async(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze paths with Playwright and LLM."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            try:
                # Step 1: Crawl all paths and group similar responses
                logger.info(f"[Job {self.job.id}] Step 1: Crawling {len(paths)} paths...")
                crawl_results = await self._crawl_paths(browser, paths)

                # Step 2: Group similar responses
                logger.info(f"[Job {self.job.id}] Step 2: Grouping similar responses...")
                grouped_pages = self._group_similar_responses(crawl_results)

                logger.info(f"[Job {self.job.id}] Grouped {len(crawl_results)} pages into {len(grouped_pages)} groups")

                # Step 3: Analyze representative pages with LLM
                logger.info(f"[Job {self.job.id}] Step 3: Analyzing {len(grouped_pages)} representative pages with LLM...")
                analysis_results = await self._analyze_with_llm(grouped_pages)

                return analysis_results

            finally:
                await browser.close()

    async def _crawl_paths(
        self,
        browser: Browser,
        paths: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Crawl paths with Playwright to get rendered content."""
        crawl_results = []

        for idx, path_info in enumerate(paths, 1):
            url = path_info.get("url")
            if not url:
                continue

            try:
                logger.info(f"  [{idx}/{len(paths)}] Crawling: {url[:70]}...")

                page = await browser.new_page()

                # Navigate with timeout
                response = await page.goto(url, wait_until="networkidle", timeout=30000)

                # Get page content
                html_content = await page.content()
                visible_text = await page.inner_text('body')
                title = await page.title()

                # Get status code and content length
                status_code = response.status if response else 0
                content_length = len(html_content)

                # Take screenshot for evidence
                screenshot_path = os.path.join(self.output_dir, f"{hashlib.md5(url.encode()).hexdigest()}.png")
                await page.screenshot(path=screenshot_path, full_page=False)

                crawl_results.append({
                    "url": url,
                    "status_code": status_code,
                    "content_length": content_length,
                    "title": title,
                    "html_content": html_content[:50000],  # Limit to 50k chars
                    "visible_text": visible_text[:20000],  # Limit to 20k chars
                    "screenshot_path": screenshot_path,
                    "risk_level": path_info.get("risk_level", "info"),
                })

                await page.close()

                logger.info(f"    ✓ Status: {status_code}, Size: {content_length} bytes")

            except Exception as e:
                logger.error(f"    ✗ Failed to crawl {url}: {e}")
                continue

        return crawl_results

    def _group_similar_responses(
        self,
        crawl_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Group similar responses by status code and content size."""
        grouped_pages = []

        for crawl_data in crawl_results:
            status_code = crawl_data["status_code"]
            content_length = crawl_data["content_length"]
            url = crawl_data["url"]

            # Find matching group
            matched_group = None
            for group in self.response_groups:
                if group.matches(status_code, content_length, tolerance=0.1):
                    matched_group = group
                    break

            # Add to existing group or create new one
            if matched_group:
                matched_group.add_url(url)
                logger.debug(f"    Grouped: {url[:50]} → Group {self.response_groups.index(matched_group)}")
            else:
                new_group = ResponseGroup(status_code, content_length)
                new_group.add_url(url)
                self.response_groups.append(new_group)
                grouped_pages.append(crawl_data)
                logger.debug(f"    New group: {url[:50]} (Status: {status_code}, Size: {content_length})")

        return grouped_pages

    async def _analyze_with_llm(
        self,
        pages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze pages with LLM for vulnerability detection."""
        analysis_results = []

        for idx, page_data in enumerate(pages, 1):
            url = page_data["url"]

            try:
                logger.info(f"  [{idx}/{len(pages)}] Analyzing with LLM: {url[:60]}...")

                # Build LLM prompt
                prompt = self._build_analysis_prompt(page_data)

                # Call AI service
                response = self.ai_service.generate(prompt)

                # Parse JSON response
                analysis = self._parse_llm_response(response, page_data)

                if analysis:
                    # Add findings to tracking
                    for finding in analysis.get("findings", []):
                        finding_id = finding.get("id")
                        if finding_id and finding_id not in self.finding_ids_seen:
                            self.finding_ids_seen.add(finding_id)
                            self.analyzed_findings.append({
                                **finding,
                                "url": url,
                                "page_type": analysis.get("page_type"),
                            })

                    analysis_results.append(analysis)

                    findings_count = len(analysis.get("findings", []))
                    logger.info(f"    ✓ Page Type: {analysis.get('page_type')}, Findings: {findings_count}")
                else:
                    logger.warning(f"    ⚠ Failed to parse LLM response for {url}")

            except Exception as e:
                logger.error(f"    ✗ LLM analysis failed for {url}: {e}")
                continue

        return analysis_results

    def _build_analysis_prompt(self, page_data: Dict[str, Any]) -> str:
        """Build LLM prompt for security analysis."""
        url = page_data["url"]
        title = page_data.get("title", "")
        visible_text = page_data.get("visible_text", "")[:8000]  # Limit to 8k chars

        # Build findings context (what we've found so far)
        findings_context = "\n".join([
            f"- {fid}: {vec}"
            for finding in self.analyzed_findings
            for fid, vec in [(finding.get('id'), finding.get('vector'))]
        ][:20])  # Show last 20 findings

        prompt = f"""You are an expert penetration tester analyzing a web page for security vulnerabilities.

URL: {url}
Title: {title}

Page Content (first 8000 chars):
{visible_text}

Previously discovered findings (reuse IDs for similar vulnerabilities):
{findings_context if findings_context else "None yet"}

Analyze this page and provide a structured JSON security report with the following format:

{{
    "page_type": "LoginPage | AdminPanel | API | Dashboard | Form | ContactPage | Other",
    "findings": [
        {{
            "id": "vuln-XXX",
            "vector": "SQL Injection | XSS | CSRF | IDOR | Open Redirect | Info Disclosure | Hardcoded Secrets | Broken Auth | etc.",
            "evidence": "Detailed explanation of the vulnerability with specific code/elements",
            "method": "GET | POST | PUT | DELETE | PATCH | ''",
            "parameters": ["param1", "param2"],
            "payload": ["example_payload1", "example_payload2"],
            "related_endpoints": ["/endpoint/path1", "/endpoint/path2"],
            "context": "Brief context for this finding"
        }}
    ],
    "technologies": ["Technology name with version if detectable"],
    "summary": "Brief summary of key security findings"
}}

IMPORTANT RULES:
1. Reuse finding IDs (vuln-XXX) when the same vulnerability appears across pages
2. Only include findings with concrete evidence - no speculation
3. Provide realistic payloads for attack vectors
4. Classify page type accurately based on observed elements
5. Return ONLY valid JSON, no markdown formatting

Respond strictly in JSON format:"""

        return prompt

    def _parse_llm_response(
        self,
        response: str,
        page_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Parse LLM JSON response."""
        try:
            # Remove markdown code blocks if present
            response_text = response.strip()
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]

            # Parse JSON
            analysis = json.loads(response_text.strip())

            # Add metadata
            analysis['url'] = page_data['url']
            analysis['analyzed_at'] = datetime.now().isoformat()
            analysis['status_code'] = page_data.get('status_code')

            return analysis

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}")
            logger.debug(f"Response: {response[:500]}")

            # Fallback: create basic analysis from text
            return {
                "url": page_data['url'],
                "page_type": "Unknown",
                "findings": [],
                "technologies": [],
                "summary": response[:500] if response else "Analysis failed",
                "analyzed_at": datetime.now().isoformat()
            }

    def _save_findings_to_db(self, phase: Phase):
        """Save findings to database as Finding records."""
        logger.info(f"[Job {self.job.id}] Saving {len(self.analyzed_findings)} findings to database...")

        saved_count = 0

        for finding_data in self.analyzed_findings:
            try:
                # Map to Finding model
                finding = Finding(
                    job_id=self.job.id,
                    title=f"{finding_data.get('vector', 'Security Finding')} at {finding_data.get('url', 'Unknown')}",
                    description=finding_data.get('evidence', ''),
                    finding_type='web_analysis',
                    severity=self._map_severity(finding_data.get('vector', '')),
                    url=finding_data.get('url'),
                    evidence=json.dumps({
                        "finding_id": finding_data.get('id'),
                        "vector": finding_data.get('vector'),
                        "method": finding_data.get('method'),
                        "parameters": finding_data.get('parameters', []),
                        "payload": finding_data.get('payload', []),
                        "related_endpoints": finding_data.get('related_endpoints', []),
                        "context": finding_data.get('context', ''),
                        "page_type": finding_data.get('page_type'),
                    }),
                    is_categorized=False,  # Will be categorized by findings_populator
                )

                self.db.add(finding)
                saved_count += 1

            except Exception as e:
                logger.error(f"Failed to save finding {finding_data.get('id')}: {e}")
                continue

        self.db.commit()
        logger.info(f"  ✓ Saved {saved_count} findings to database")

    def _map_severity(self, vector: str) -> str:
        """Map vulnerability vector to severity level."""
        vector_lower = vector.lower()

        # Critical patterns
        if any(kw in vector_lower for kw in [
            'rce', 'remote code execution', 'command injection',
            'sql injection', 'authentication bypass'
        ]):
            return 'Critical'

        # High patterns
        if any(kw in vector_lower for kw in [
            'xss', 'cross-site scripting', 'csrf', 'ssrf',
            'idor', 'privilege escalation', 'xxe'
        ]):
            return 'High'

        # Medium patterns
        if any(kw in vector_lower for kw in [
            'information disclosure', 'open redirect',
            'weak', 'misconfiguration'
        ]):
            return 'Medium'

        # Default
        return 'Low'
