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
from services.ai.prompts import get_web_analysis_single_page_prompt, get_web_analysis_batch_prompt
from services.utils.output_manager import get_output_manager
from services.utils.vulnerability_deduplicator import VulnerabilityDeduplicator
from services.utils.interactive_confirmer import InteractiveConfirmer

logger = logging.getLogger(__name__)


class ResponseGroup:
    """Groups identical responses for pruning."""

    def __init__(self, status_code: int, content_length: int, content_hash: str):
        self.status_code = status_code
        self.content_length = content_length
        self.content_hash = content_hash  # SHA256 hash of content
        self.urls: List[str] = []
        self.representative_url: Optional[str] = None

    def add_url(self, url: str):
        """Add URL to this group."""
        self.urls.append(url)
        # Representative is the shortest/simplest URL
        if not self.representative_url or len(url) < len(self.representative_url):
            self.representative_url = url

    def matches(self, status_code: int, content_length: int, content_hash: str) -> bool:
        """Check if response matches this group (exact match by status + size + hash)."""
        return (
            self.status_code == status_code and
            self.content_length == content_length and
            self.content_hash == content_hash
        )


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

        # Initialize deduplicator
        self.deduplicator = VulnerabilityDeduplicator(
            job_id=str(job.id),
            similarity_threshold=0.90
        )

        # Tracking
        self.response_groups: List[ResponseGroup] = []
        self.analyzed_findings: List[Dict[str, Any]] = []
        self.finding_ids_seen: Set[str] = set()

        logger.info(f"WebAnalysisPhase initialized for job {job.id}")

    def execute(self, web_enum_data: Dict[str, Any], max_pages: int = None, max_iterations: int = 5) -> Phase:
        """
        Execute web analysis phase with recursive discovery.

        Args:
            web_enum_data: Data from web enumeration phase
            max_pages: Maximum pages to analyze per iteration (None = unlimited)
            max_iterations: Maximum recursive iterations (default: 3, always-on)

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
            logger.info(f"[Job {self.job.id}] STARTING WEB ANALYSIS PHASE (RECURSIVE)")
            logger.info(f"  Max iterations: {max_iterations}")
            logger.info("=" * 80)

            # Extract high-priority paths from web enumeration
            high_priority_paths = self._extract_high_priority_paths(web_enum_data, max_pages)

            if not high_priority_paths:
                logger.warning(f"[Job {self.job.id}] No high-priority paths found")
                phase.status = "completed"
                phase.data = {"error": "No paths to analyze"}
                self.db.commit()
                return phase

            # Track all findings across iterations
            all_confirmed_findings = []
            iteration_stats = []
            stopping_reason = None

            # Recursive discovery loop (always 3 iterations)
            for iteration in range(1, max_iterations + 1):
                logger.info("\n" + "=" * 80)
                logger.info(f"[Job {self.job.id}] ITERATION {iteration}/{max_iterations}")
                logger.info("=" * 80)

                if iteration == 1:
                    paths_to_analyze = high_priority_paths
                    logger.info(f"  Analyzing {len(paths_to_analyze)} initial paths from web enumeration")
                else:
                    # Extract new URLs from previous iteration's confirmed findings
                    paths_to_analyze = self._extract_new_urls_from_findings(all_confirmed_findings)

                    if not paths_to_analyze:
                        stopping_reason = f"No new URLs discovered in iteration {iteration-1}"
                        logger.info(f"  {stopping_reason}, stopping")
                        break

                    logger.info(f"  Analyzing {len(paths_to_analyze)} new URLs from iteration {iteration-1}")

                # Clear findings for this iteration
                self.analyzed_findings = []
                self.finding_ids_seen = set()
                self.response_groups = []

                # Run async analysis for this iteration
                logger.info(f"[Job {self.job.id}] Step 1-3: Crawling and analyzing paths...")
                analysis_results = asyncio.run(self._analyze_paths_async(paths_to_analyze))

                # Step 4: Smart Deduplication
                logger.info(f"[Job {self.job.id}] Step 4: Deduplicating {len(self.analyzed_findings)} findings...")
                deduplicated_findings = self._deduplicate_findings()

                # Step 5: Interactive Confirmation
                logger.info(f"[Job {self.job.id}] Step 5: Interactive confirmation of {len(deduplicated_findings)} findings...")
                confirmed_findings = asyncio.run(self._confirm_findings_interactive(deduplicated_findings))

                # Filter: Only keep CONFIRMED findings for recursion
                iteration_confirmed = [
                    f for f in confirmed_findings
                    if f.get('confirmation_status') == 'CONFIRMED'
                ]

                # Add to all findings
                all_confirmed_findings.extend(iteration_confirmed)

                # Track iteration stats
                iteration_stats.append({
                    'iteration': iteration,
                    'paths_analyzed': len(paths_to_analyze),
                    'raw_findings': len(self.analyzed_findings),
                    'unique_findings': len(deduplicated_findings),
                    'confirmed': len(iteration_confirmed),
                    'false_positives': len([f for f in confirmed_findings if f.get('confirmation_status') == 'FALSE_POSITIVE']),
                })

                logger.info(f"[Job {self.job.id}] Iteration {iteration} complete:")
                logger.info(f"  Paths analyzed: {len(paths_to_analyze)}")
                logger.info(f"  Confirmed findings: {len(iteration_confirmed)}")

                # Stopping condition check (after iteration 1)
                if iteration > 1:
                    # Calculate success rate for this iteration
                    tested_count = len(deduplicated_findings)
                    confirmed_count = len(iteration_confirmed)
                    success_rate = (confirmed_count / tested_count * 100) if tested_count > 0 else 0

                    logger.info(f"  Success rate: {success_rate:.1f}% ({confirmed_count}/{tested_count})")

                    # Priority 1: Max iterations reached (hard stop)
                    if iteration >= max_iterations:
                        stopping_reason = f"Max iterations ({max_iterations}) reached"
                        logger.info(f"  {stopping_reason}, stopping")
                        break

                    # Priority 2: Success rate < 10% (diminishing returns)
                    if success_rate < 10 and tested_count > 5:  # Need at least 5 tests
                        stopping_reason = f"Success rate below 10% ({success_rate:.1f}%) - diminishing returns"
                        logger.warning(f"  {stopping_reason}, stopping early")
                        break

                    # Stop if no new confirmed findings
                    if not iteration_confirmed:
                        stopping_reason = f"No confirmed findings in iteration {iteration}"
                        logger.info(f"  {stopping_reason}, stopping")
                        break
                elif iteration == 1 and not iteration_confirmed:
                    # Special case: iteration 1 with no findings
                    stopping_reason = "No confirmed findings in iteration 1"
                    logger.info(f"  {stopping_reason}, stopping")
                    break

            # Calculate final statistics
            total_confirmed = len(all_confirmed_findings)
            total_iterations_run = len(iteration_stats)

            # Set default stopping reason if not set
            if not stopping_reason:
                stopping_reason = "All iterations completed successfully"

            # Save results to phase
            phase.data = {
                "total_paths_discovered": len(web_enum_data.get("discovered_paths", [])),
                "high_priority_paths": len(high_priority_paths),
                "max_iterations": max_iterations,
                "iterations_completed": total_iterations_run,
                "stopping_reason": stopping_reason,
                "iteration_stats": iteration_stats,
                "total_confirmed_findings": total_confirmed,
                "findings": all_confirmed_findings,  # All confirmed findings from all iterations
                "deduplication_stats": self.deduplicator.get_statistics(),
            }
            phase.status = "completed"
            self.db.commit()

            # Note: Findings are extracted by findings_populator during report generation
            # This ensures consistent KB matching and AI categorization across all finding types

            logger.info("\n" + "=" * 80)
            logger.info(f"[Job {self.job.id}] WEB ANALYSIS PHASE COMPLETED (RECURSIVE)")
            logger.info("=" * 80)
            logger.info(f"  Iterations completed: {total_iterations_run}/{max_iterations}")
            logger.info(f"  Stopping reason: {stopping_reason}")
            logger.info(f"  Total confirmed findings: {total_confirmed}")
            for idx, stats in enumerate(iteration_stats, 1):
                success_rate = (stats['confirmed'] / stats['unique_findings'] * 100) if stats['unique_findings'] > 0 else 0
                logger.info(f"  Iteration {idx}: {stats['confirmed']} confirmed from {stats['paths_analyzed']} paths (success: {success_rate:.1f}%)")
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

    def _extract_new_urls_from_findings(
        self,
        confirmed_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Extract new URLs from confirmed findings for recursive discovery.

        Looks for:
        - related_endpoints
        - URLs mentioned in evidence
        - URLs in confirmation_result trace

        Returns:
            List of path dicts compatible with _analyze_paths_async
        """
        new_urls = set()

        for finding in confirmed_findings:
            # Extract from related_endpoints
            related_endpoints = finding.get('related_endpoints', [])
            for endpoint in related_endpoints:
                if isinstance(endpoint, str) and endpoint.startswith('http'):
                    new_urls.add(endpoint)

            # Extract from affected_locations
            affected_locations = finding.get('affected_locations', [])
            for loc in affected_locations:
                url = loc.get('url', '')
                if url and url.startswith('http'):
                    # Also extract any URLs mentioned in evidence
                    evidence = loc.get('evidence', {})
                    raw_snippet = evidence.get('raw_snippet', '')
                    if raw_snippet:
                        # Extract URLs from snippet
                        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                        found_urls = re.findall(url_pattern, raw_snippet)
                        new_urls.update(found_urls)

            # Extract from confirmation_result network capture
            confirmation_result = finding.get('confirmation_result', {})
            network_capture = confirmation_result.get('network_capture', {})
            network_requests = network_capture.get('network_requests', [])
            for request in network_requests:
                url = request.get('url', '')
                if url and url.startswith('http'):
                    new_urls.add(url)

        # Convert to path format
        paths = []
        for url in new_urls:
            paths.append({
                'url': url,
                'risk_level': 'medium',  # Default risk for discovered URLs
                'status_code': 200,  # Assumed
                'category': 'Discovered',
                'source': 'recursive_discovery'
            })

        logger.info(f"  Extracted {len(paths)} new URLs from {len(confirmed_findings)} confirmed findings")

        # Deduplicate and limit to reasonable number
        unique_paths = []
        seen = set()
        for path in paths:
            url = path['url']
            if url not in seen:
                seen.add(url)
                unique_paths.append(path)

        # Limit to top 50 URLs per iteration to prevent explosion
        if len(unique_paths) > 50:
            logger.info(f"  Limiting to top 50 URLs (found {len(unique_paths)})")
            unique_paths = unique_paths[:50]

        return unique_paths

    def _extract_high_priority_paths(
        self,
        web_enum_data: Dict[str, Any],
        max_paths: Optional[int]
    ) -> List[Dict[str, Any]]:
        """Extract high-priority paths from web enumeration data."""
        logger.info(f"[DEBUG] Web enum data keys: {list(web_enum_data.keys())}")

        # ✅ FIXED: Correct data structure - paths are in path_analysis.analysis.findings
        path_analysis = web_enum_data.get('path_analysis', {})
        analysis = path_analysis.get('analysis', {})
        discovered_paths = analysis.get('findings', [])

        logger.info(f"[DEBUG] Extracted {len(discovered_paths)} paths from path_analysis.analysis.findings")

        if not discovered_paths:
            return []

        # Transform path_analyzer findings to web_analysis format
        # path_analyzer has: {'path': '/admin', 'risk': 'high', ...}
        # web_analysis needs: {'url': 'http://target/admin', 'risk_level': 'high', ...}
        transformed_paths = []
        for finding in discovered_paths:
            # Build full URL from path
            path = finding.get('path', finding.get('clean_path', ''))
            if not path:
                continue

            # Get base URL from web_services
            base_url = ""
            web_services = web_enum_data.get('web_services', [])
            if web_services:
                base_url = web_services[0].get('url', '')

            transformed_paths.append({
                'url': f"{base_url}{path}" if base_url else path,
                'risk_level': finding.get('risk', 'low'),
                'status_code': finding.get('status_code', 200),
                'category': finding.get('category', 'Unknown'),
                'original_finding': finding
            })

        discovered_paths = transformed_paths
        logger.info(f"[DEBUG] Transformed {len(discovered_paths)} paths with URLs")

        # Sort by risk level: critical > high > medium > low
        risk_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        sorted_paths = sorted(
            discovered_paths,
            key=lambda p: (
                risk_priority.get(p.get("risk_level", "info"), 5),
                -p.get("status_code", 0)  # Prefer accessible pages (200, 403, 401)
            )
        )

        # Take top N paths (or all if max_paths is None)
        if max_paths is None:
            return sorted_paths  # Analyze ALL paths
        else:
            return sorted_paths[:max_paths]  # Analyze top N

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

                # Compute content hash for exact duplicate detection
                content_hash = hashlib.sha256(html_content.encode()).hexdigest()

                # Take screenshot for evidence
                screenshot_path = os.path.join(self.output_dir, f"{hashlib.md5(url.encode()).hexdigest()}.png")
                await page.screenshot(path=screenshot_path, full_page=False)

                crawl_results.append({
                    "url": url,
                    "status_code": status_code,
                    "content_length": content_length,
                    "content_hash": content_hash,
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
        """
        Group IDENTICAL responses by status code + content size + content hash.

        ✅ Different content = Different analysis
        Only groups truly identical responses (same hash) to avoid duplicate AI calls.
        """
        grouped_pages = []

        for crawl_data in crawl_results:
            status_code = crawl_data["status_code"]
            content_length = crawl_data["content_length"]
            content_hash = crawl_data["content_hash"]
            url = crawl_data["url"]

            # Find matching group (exact match: status + size + hash)
            matched_group = None
            for group in self.response_groups:
                if group.matches(status_code, content_length, content_hash):
                    matched_group = group
                    break

            # Add to existing group or create new one
            if matched_group:
                matched_group.add_url(url)
                logger.debug(f"    Grouped: {url[:50]} → Group {self.response_groups.index(matched_group)} (identical content)")
            else:
                new_group = ResponseGroup(status_code, content_length, content_hash)
                new_group.add_url(url)
                self.response_groups.append(new_group)
                grouped_pages.append(crawl_data)
                logger.debug(f"    New group: {url[:50]} (Status: {status_code}, Size: {content_length}, Hash: {content_hash[:8]}...)")

        return grouped_pages

    async def _analyze_with_llm(
        self,
        pages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze pages with LLM using BATCH PROCESSING for efficiency.

        Strategy: Process 5 pages per AI request to reduce API calls.
        With 10 req/min limit: 10 requests × 5 pages = 50 pages/minute (vs 10 before!)
        """
        analysis_results = []

        # Batch size: Number of pages per AI request
        # Gemini has 10 req/min limit, so we optimize by batching
        BATCH_SIZE = 5

        # Calculate number of batches
        total_pages = len(pages)
        num_batches = (total_pages + BATCH_SIZE - 1) // BATCH_SIZE

        logger.info(f"  Processing {total_pages} pages in {num_batches} batches (batch size: {BATCH_SIZE})")

        for batch_idx in range(0, total_pages, BATCH_SIZE):
            batch_pages = pages[batch_idx:batch_idx + BATCH_SIZE]
            batch_num = (batch_idx // BATCH_SIZE) + 1

            try:
                logger.info(f"  Batch [{batch_num}/{num_batches}]: Analyzing {len(batch_pages)} pages...")

                # Build batch prompt
                prompt = self._build_batch_analysis_prompt(batch_pages)

                # Call AI service ONCE for the entire batch
                response = self.ai_service.generate(prompt)

                # Parse batch response
                batch_results = self._parse_batch_llm_response(response, batch_pages)

                if batch_results:
                    for analysis in batch_results:
                        url = analysis.get("url", "")

                        # Add findings to tracking
                        for finding in analysis.get("findings", []):
                            finding_id = finding.get("id")
                            if finding_id and finding_id not in self.finding_ids_seen:
                                self.finding_ids_seen.add(finding_id)

                                # Find screenshot path for this URL from batch_pages
                                screenshot_path = None
                                for page in batch_pages:
                                    if page.get('url') == url:
                                        screenshot_path = page.get('screenshot_path')
                                        break

                                self.analyzed_findings.append({
                                    **finding,
                                    "url": url,
                                    "page_type": analysis.get("page_type"),
                                    "screenshot_path": screenshot_path,
                                })

                        analysis_results.append(analysis)
                        findings_count = len(analysis.get("findings", []))
                        logger.info(f"    ✓ {url[:50]}: {analysis.get('page_type')} ({findings_count} findings)")
                else:
                    logger.warning(f"    ⚠ Failed to parse batch response")

                # Rate limiting: Wait 6 seconds between batches to stay under 10 req/min
                # 10 requests/min = 1 request every 6 seconds
                if batch_num < num_batches:
                    logger.info(f"    ⏱ Rate limit: waiting 6s before next batch...")
                    await asyncio.sleep(6)

            except Exception as e:
                logger.error(f"    ✗ Batch analysis failed: {e}")
                continue

        logger.info(f"  ✓ Batch processing complete: {len(analysis_results)} pages analyzed, {len(self.analyzed_findings)} findings")
        return analysis_results

    def _build_analysis_prompt(self, page_data: Dict[str, Any]) -> str:
        """Build LLM prompt for security analysis using centralized prompts."""
        url = page_data["url"]
        title = page_data.get("title", "")
        visible_text = page_data.get("visible_text", "")

        # Build findings context (what we've found so far)
        findings_context = "\n".join([
            f"- {fid}: {vec}"
            for finding in self.analyzed_findings
            for fid, vec in [(finding.get('id'), finding.get('vector'))]
        ][:20])  # Show last 20 findings

        return get_web_analysis_single_page_prompt(
            url=url,
            title=title,
            visible_text=visible_text,
            findings_context=findings_context
        )

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

    def _build_batch_analysis_prompt(self, batch_pages: List[Dict[str, Any]]) -> str:
        """
        Build LLM prompt for BATCH analysis of multiple pages using centralized prompts.
        This reduces API calls by analyzing multiple pages in one request.
        """
        # Build findings context
        findings_context = "\n".join([
            f"- {fid}: {vec}"
            for finding in self.analyzed_findings
            for fid, vec in [(finding.get('id'), finding.get('vector'))]
        ][:20])

        return get_web_analysis_batch_prompt(
            batch_pages=batch_pages,
            findings_context=findings_context
        )

    def _parse_batch_llm_response(
        self,
        response: str,
        batch_pages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Parse LLM JSON response for batch analysis."""
        try:
            # Remove markdown code blocks if present
            response_text = response.strip()
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]

            # Parse JSON array
            batch_analyses = json.loads(response_text.strip())

            # Ensure it's a list
            if not isinstance(batch_analyses, list):
                logger.error("Batch response is not an array")
                return []

            # Add metadata to each analysis
            for analysis in batch_analyses:
                analysis['analyzed_at'] = datetime.now().isoformat()

                # Try to match URL to original page data
                url = analysis.get('url', '')
                matching_page = next((p for p in batch_pages if p['url'] == url), None)
                if matching_page:
                    analysis['status_code'] = matching_page.get('status_code')

            logger.info(f"    Parsed {len(batch_analyses)} page analyses from batch")
            return batch_analyses

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse batch LLM JSON response: {e}")
            logger.debug(f"Response: {response[:500]}")
            return []
        except Exception as e:
            logger.error(f"Error parsing batch response: {e}")
            return []

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
                        "screenshot_path": finding_data.get('screenshot_path'),
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

    async def _confirm_findings_interactive(
        self,
        deduplicated_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Validate all deduplicated findings with interactive confirmation.

        Args:
            deduplicated_findings: List of unique findings from deduplication

        Returns:
            List of findings with confirmation results
        """
        logger.info(f"[Job {self.job.id}] Starting interactive confirmation of {len(deduplicated_findings)} findings...")

        confirmed_findings = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            confirmer = InteractiveConfirmer(timeout=10000)

            try:
                for idx, finding in enumerate(deduplicated_findings, 1):
                    # Get first affected location for testing
                    affected_locations = finding.get('affected_locations', [])
                    if not affected_locations:
                        logger.warning(f"  [{idx}/{len(deduplicated_findings)}] No affected locations, skipping")
                        finding['confirmation_status'] = 'SKIPPED'
                        finding['confirmation_result'] = None
                        confirmed_findings.append(finding)
                        continue

                    test_url = affected_locations[0].get('url', '')
                    if not test_url:
                        logger.warning(f"  [{idx}/{len(deduplicated_findings)}] No URL, skipping")
                        finding['confirmation_status'] = 'SKIPPED'
                        finding['confirmation_result'] = None
                        confirmed_findings.append(finding)
                        continue

                    logger.info(f"  [{idx}/{len(deduplicated_findings)}] Confirming: {finding.get('vuln_type')} at {test_url[:50]}...")

                    try:
                        # Navigate to page
                        page = await browser.new_page()
                        response = await page.goto(test_url, wait_until="networkidle", timeout=30000)

                        if not response:
                            logger.warning(f"    ✗ Failed to load page")
                            finding['confirmation_status'] = 'ERROR'
                            finding['confirmation_result'] = {'error': 'Failed to load page'}
                            confirmed_findings.append(finding)
                            await page.close()
                            continue

                        # Wait for JavaScript
                        await page.wait_for_timeout(2000)

                        # Run interactive confirmation
                        # Extract original finding data for confirmer
                        original_finding = finding.get('original_finding', {})
                        if not original_finding:
                            # Reconstruct finding for confirmer
                            original_finding = {
                                'id': finding.get('vuln_id'),
                                'vuln_type': finding.get('vuln_type'),
                                'vector': finding.get('vector'),
                                'primary_indicator': finding.get('primary_indicator'),
                                'evidence': affected_locations[0].get('evidence', {})
                            }

                        confirmation_result = await confirmer.confirm_finding(page, original_finding, test_url)

                        # Add confirmation status to finding
                        finding['confirmation_status'] = confirmation_result.get('status', 'AMBIGUOUS')
                        finding['confirmation_result'] = confirmation_result

                        # Log result
                        status = confirmation_result.get('status')
                        if status == 'CONFIRMED':
                            logger.info(f"    ✓ CONFIRMED: {confirmation_result.get('reasoning', '')[:80]}")
                        elif status == 'FALSE_POSITIVE':
                            logger.info(f"    ✗ FALSE POSITIVE: {confirmation_result.get('reasoning', '')[:80]}")
                        else:
                            logger.warning(f"    ? AMBIGUOUS: {confirmation_result.get('reasoning', '')[:80]}")

                        # NEW: Test for XSS vulnerabilities on this page
                        # Run XSS testing after confirmation (page is already loaded)
                        try:
                            logger.info(f"    🔍 Testing page for XSS vulnerabilities...")
                            xss_result = await confirmer.test_xss_on_page(page, test_url)

                            # Store XSS test results in the finding
                            finding['xss_test_result'] = xss_result

                            # Log XSS results
                            if xss_result.get('xss_confirmed'):
                                successful_payloads = xss_result.get('successful_payloads', [])
                                logger.info(f"    ✓ XSS CONFIRMED: {len(successful_payloads)} successful payload(s)")
                                for payload_info in successful_payloads:
                                    logger.info(f"      → Field: {payload_info.get('field')}, Payload: {payload_info.get('payload')[:50]}...")
                            else:
                                input_fields = xss_result.get('input_fields_found', 0)
                                if input_fields > 0:
                                    logger.info(f"    ✓ No XSS found ({input_fields} field(s) tested)")
                                else:
                                    logger.info(f"    ℹ No input fields to test")
                        except Exception as xss_error:
                            logger.warning(f"    ⚠ XSS testing failed: {xss_error}")
                            finding['xss_test_result'] = {'error': str(xss_error)}

                        confirmed_findings.append(finding)

                        await page.close()

                        # Rate limiting: Wait 6 seconds between confirmations
                        if idx < len(deduplicated_findings):
                            logger.info(f"    ⏱ Rate limit: waiting 6s before next confirmation...")
                            await asyncio.sleep(6)

                    except Exception as e:
                        logger.error(f"    ✗ Confirmation failed: {e}")
                        finding['confirmation_status'] = 'ERROR'
                        finding['confirmation_result'] = {'error': str(e)}
                        confirmed_findings.append(finding)

            finally:
                await browser.close()

        # Log summary
        confirmed_count = len([f for f in confirmed_findings if f.get('confirmation_status') == 'CONFIRMED'])
        false_positive_count = len([f for f in confirmed_findings if f.get('confirmation_status') == 'FALSE_POSITIVE'])
        error_count = len([f for f in confirmed_findings if f.get('confirmation_status') == 'ERROR'])

        logger.info(f"[Job {self.job.id}] Interactive confirmation complete:")
        logger.info(f"  Total tested: {len(confirmed_findings)}")
        logger.info(f"  Confirmed: {confirmed_count}")
        logger.info(f"  False positives: {false_positive_count}")
        logger.info(f"  Errors: {error_count}")

        return confirmed_findings

    def _deduplicate_findings(self) -> List[Dict[str, Any]]:
        """
        Deduplicate findings using ChromaDB RAG semantic similarity.

        Returns:
            List of unique findings with merged locations
        """
        logger.info(f"[Job {self.job.id}] Starting deduplication of {len(self.analyzed_findings)} findings...")

        # Process each finding through deduplicator
        for finding in self.analyzed_findings:
            url = finding.get('url', 'unknown')
            metadata = {
                'page_type': finding.get('page_type'),
                'screenshot_path': finding.get('screenshot_path')
            }

            # Process through deduplicator
            result = self.deduplicator.process_finding(finding, url, metadata)

            # Log result
            if result['action'] == 'new':
                logger.debug(f"  🆕 New: {finding.get('vuln_type')} at {url[:50]}")
            else:
                logger.debug(f"  ✓ Merged: {finding.get('vuln_type')} → {result['vuln_id']}")

        # Get deduplicated findings
        deduplicated = self.deduplicator.get_deduplicated_findings()
        stats = self.deduplicator.get_statistics()

        # Save deduplication report
        report_path = self.deduplicator.save_report()

        logger.info(f"[Job {self.job.id}] Deduplication complete:")
        logger.info(f"  Input: {stats['total_processed']} findings")
        logger.info(f"  Output: {stats['unique_findings']} unique findings")
        logger.info(f"  Exact matches: {stats['exact_signature_matches']}")
        logger.info(f"  Semantic matches: {stats['semantic_matches']}")
        logger.info(f"  Reduction: {stats['deduplication_ratio']}")
        logger.info(f"  Report saved: {report_path}")

        return deduplicated

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
