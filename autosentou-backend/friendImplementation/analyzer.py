"""
services/utils/analyzer.py
AI-powered analysis engine using Gemini for security assessment
"""
import os
import logging
import asyncio
import hashlib
import time
from typing import Dict, Any, List, Optional, Set, Literal
from urllib.parse import urlparse
from datetime import datetime
import json
from pathlib import Path

# Import schema converter
try:
    from .schema_converter import SchemaConverterV2, convert_analysis_to_v2
    SCHEMA_CONVERTER_AVAILABLE = True
except ImportError:
    SCHEMA_CONVERTER_AVAILABLE = False
    logging.warning("Schema converter not available")

# ChromaDB imports
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logging.warning("ChromaDB not installed. Run: pip install chromadb")

# Gemini imports
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logging.warning("Gemini not installed. Run: pip install google-generativeai")

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """
    AI-powered security analyzer using Gemini for pentesting insights.
    Supports multiple analysis modes: realtime, batch, smart, and template-aware.
    """
    
    def __init__(
        self,
        gemini_api_key: str,
        job_id: str,
        chroma_persist_dir: str = "./chroma_db",
        max_concurrent: int = 1,  # Changed from 3 to 1 for free tier
        analysis_mode: Literal["realtime", "batch", "smart"] = "smart",
        template_aware_config: Optional[Dict[str, Any]] = None,
        record_dir: str = "./record",
        use_v2_schema: bool = True,
    ):
        """
        Initialize Security Analyzer.
        
        Args:
            gemini_api_key: Gemini API key
            job_id: Unique job identifier
            chroma_persist_dir: ChromaDB persistence directory
            max_concurrent: DEPRECATED - Always uses sequential processing (1) for rate limit compliance
            analysis_mode: Analysis strategy
                - "realtime": Analyze immediately as data comes in
                - "batch": Analyze all data at once (sequentially)
                - "smart": Analyze with intelligent scheduling (sequentially)
            template_aware_config: Configuration for template-aware analysis
            record_dir: Directory to save JSON records
            use_v2_schema: Use v2 compact schema format (default: True)
        """
        if not GEMINI_AVAILABLE:
            raise ImportError("Google Generative AI not installed. Run: pip install google-generativeai")
        
        if not CHROMADB_AVAILABLE:
            raise ImportError("ChromaDB not installed. Run: pip install chromadb")
        
        self.note = []
        self.note_set = set()

        self.gemini_api_key = gemini_api_key
        self.job_id = job_id
        self.max_concurrent = 1  # Always 1 for rate limit compliance
        self.analysis_mode = analysis_mode
        self.record_dir = record_dir
        self.use_v2_schema = use_v2_schema
        
        # Create record directory structure
        self.job_record_dir = Path(record_dir) / job_id
        self.job_record_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Gemini
        genai.configure(api_key=gemini_api_key)
        self.gemini_model = genai.GenerativeModel('gemini-2.5-flash')
        
        # Rate limiting for Gemini free tier: 10 requests per minute
        # To be safe, we'll aim for 8 requests per minute = 1 request every 7.5 seconds
        self._last_api_call = 0
        self._min_delay_between_calls = 7.5  # 7.5 seconds between API calls (safe margin)
        self._requests_in_last_minute = []  # Track request timestamps
        
        # Initialize ChromaDB
        self.chroma_client = chromadb.PersistentClient(
            path=chroma_persist_dir,
            settings=Settings(anonymized_telemetry=False)
        )
        
        # Collection for analyzed results
        self.analysis_collection = self.chroma_client.get_or_create_collection(
            name=f"analysised_job_{job_id}",
            metadata={"description": "Gemini analysis results"}
        )
        
        # Collection for persistent memory (findings notes)
        self.memory_collection = self.chroma_client.get_or_create_collection(
            name=f"memory_findings_{job_id}",
            metadata={"description": "Persistent memory for security findings"}
        )
        
        # Tracking
        self.analysis_results: List[Dict[str, Any]] = []
        
        logger.info(f"SecurityAnalyzer initialized for job {job_id}")
        logger.info(f"  Analysis mode: {analysis_mode}")
        logger.info(f"  Processing: Sequential (1 page at a time for rate limit compliance)")
        logger.info(f"  Schema version: {'v2 (compact)' if self.use_v2_schema else 'v1 (legacy)'}")
    
    def _generate_doc_id(self, url: str) -> str:
        """Generate unique document ID for ChromaDB."""
        return hashlib.md5(url.encode()).hexdigest()
    
    def add_memory(self, note: str, url: str = None, finding_id: str = None) -> None:
        """
        Add security finding note to persistent memory.
        
        Args:
            note: The finding note/description to store
            url: Associated URL (optional)
            finding_id: Associated finding ID (optional)
        """
        try:
            # Generate unique ID for this note
            note_id = hashlib.md5(f"{url}_{finding_id}_{note[:100]}".encode()).hexdigest()
            
            # Build metadata
            metadata = {
                'job_id': self.job_id,
                'timestamp': datetime.now().isoformat(),
                'note_preview': note[:200]
            }
            
            if url:
                metadata['url'] = url
            if finding_id:
                metadata['finding_id'] = finding_id
            
            # Store in memory collection
            self.memory_collection.add(
                ids=[note_id],
                documents=[note],
                metadatas=[metadata]
            )
            
            logger.debug(f"✓ Added memory note: {finding_id or 'general'}")
            
        except Exception as e:
            logger.error(f"Failed to add memory: {e}")
    
    def _analyze_with_gemini(
        self,
        url: str,
        content: str,
        markdown: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """Analyze page content with Gemini for pentesting insights."""
        try:
            # Prepare prompt for pentesting analysis (OPTIMIZED - reduced from 8000 to 3000 chars)
            prompt = f"""You are an expert penetration tester analyzing a web page for security assessment.
URL: {url}

Page Content (Markdown - truncated to first 8000 chars):
{markdown[:8000]}

Analyze this page and provide a structured JSON-based security report based on the following structure:

---
### Discovered Findings Ids
{self.note}

### OUTPUT STRUCTURE (Strictly Follow):

{{
    "page_type": "Classify the page (e.g., LoginPage, AdminPanel, API, Dashboard, Form, ContactPage, etc.)",
    "findings": [
        {{
            "id": "unique_identifier", // e.g., "vuln-001"
            "vector": "SQL Injection | XSS | CSRF | IDOR | Open Redirect | Info Disclosure | Hardcoded Secrets | etc.",
            "evidence": "Detailed explanation including how the issue was identified.",
            "method": "GET | POST | PUT | DELETE | ''",
            "parameters": ["param1", "param2"], // Empty array if none
            "payload": ["example_payload1", "example_payload2"], // Realistic PoC strings; empty if N/A
            "related_endpoints": ["/endpoint/path1", "/endpoint/path2"], // Specific paths only
            "context": "Context of the current discovery for noting"
        }}
    ],
    "technologies": [
        "Technology name with version if detectable (e.g., PHP 7.4, React 17)"
    ],
    "summary": "A brief summary of key findings."
}}

---

### GUIDELINES FOR ANALYSIS:

#### Important Rules:
- Reuse the finding IDs on similar vuln in similar contexts for easy query for reporting.
- Only name ids with 'vuln-XXX' format.

#### Page Classification:
Classify the page into one of the predefined types based on observed elements:
- LoginPage: Contains login form
- AdminPanel: Administrative interface
- API: Exposes RESTful endpoints or Swagger docs
- Dashboard: User-specific data display
- Form: Generic input submission
- ContactPage: Public contact form
- Other: Anything else

#### Findings Requirements:
Each finding must strictly adhere to the schema:
- Do NOT include findings without concrete evidence.
- Reuse identical vulnerability IDs across pages when referring to the same issue.
- Include payloads only if they represent realistic attack vectors.
- Ensure `related_endpoints` are full paths, not root `/`.

#### Technologies:
Identify frameworks, libraries, languages, servers, CMS, etc. based on:
- HTML comments
- Script tags
- Meta tags
- Cookies
- Headers (if present)
- Known class names or patterns

#### Example Output:
{{
    "page_type": "LoginPage",
    "findings": [
        {{
            "id": "vuln-001",
            "vector": "Information Disclosure",
            "evidence": "The page contains a direct link to `/swagger/index.html`, exposing internal API documentation.",
            "method": "GET",
            "parameters": [],
            "payload": [],
            "related_endpoints": ["/swagger/index.html"],
            "context": "Direct link to Swagger API documentation in footer"
        }}
    ],
    "technologies": ["React 18", "Express.js", "Swagger UI"],
    "summary": "Exposed API documentation at /swagger/index.html poses risk of endpoint enumeration."
}}

Respond strictly in valid JSON format matching the schema provided. No extra text or markdown formatting outside the JSON block.
"""

            # Call Gemini with timeout protection
            logger.debug(f"Calling Gemini API for {url[:50]}... (timeout: {timeout}s)")
            
            # ========== SIMPLE RATE LIMITING (SYNCHRONOUS) ==========
            # Remove requests older than 60 seconds
            current_time = time.time()
            self._requests_in_last_minute = [
                t for t in self._requests_in_last_minute 
                if current_time - t < 60
            ]
            
            # Check if we're at the limit (10 requests per minute)
            if len(self._requests_in_last_minute) >= 9:  # Keep it at 9 to be safe
                # Calculate how long to wait
                oldest_request = self._requests_in_last_minute[0]
                wait_time = 60 - (current_time - oldest_request) + 1  # +1 second buffer
                if wait_time > 0:
                    logger.warning(f"⏳ Rate limit protection: waiting {wait_time:.1f}s (9 requests in last minute)")
                    time.sleep(wait_time)
                    # Clean up old requests again after waiting
                    current_time = time.time()
                    self._requests_in_last_minute = [
                        t for t in self._requests_in_last_minute 
                        if current_time - t < 60
                    ]
            
            # Also enforce minimum delay between consecutive calls
            current_time = time.time()  # Recalculate after potential sleep
            time_since_last_call = current_time - self._last_api_call
            if time_since_last_call < self._min_delay_between_calls:
                wait_time = self._min_delay_between_calls - time_since_last_call
                logger.info(f"⏱️  Rate limiting: waiting {wait_time:.2f}s")
                time.sleep(wait_time)
            
            # Call Gemini API directly (synchronous)
            logger.info(f"🔵 Calling Gemini API for {url[:50]}...")
            response = self.gemini_model.generate_content(prompt)
            logger.info(f"🔵 Gemini API Responded for {url[:50]}...")
            
            # Update tracking
            self._last_api_call = time.time()
            self._requests_in_last_minute.append(self._last_api_call)
            response_text = response.text            # Try to parse JSON response
            try:
                # Remove markdown code blocks if present
                if '```json' in response_text:
                    response_text = response_text.split('```json')[1].split('```')[0]
                elif '```' in response_text:
                    response_text = response_text.split('```')[1].split('```')[0]
                
                analysis = json.loads(response_text.strip())
                for find in analysis["findings"]:
                    if find["id"] in self.note_set:
                        continue
                    else:       
                        self.note_set.add(find["id"])
                        self.note.append(find["id"]+"|"+find["vector"]+"|"+find["context"]+"\n")
            except json.JSONDecodeError:
                # Fallback: create structured response from text
                logger.warning(f"Failed to parse JSON from Gemini for {url}, using text response")
                analysis = {
                    "page_type": "Unknown",
                    "findings": [],
                    "technologies": [],
                    "summary": response_text[:500]
                }
            
            # Add metadata to analysis
            analysis['url'] = url
            analysis['analyzed_at'] = datetime.now().isoformat()
            
            logger.info(f"✓ Analyzed with Gemini: {url}")
            return analysis
            
        except Exception as e:
            error_msg = str(e)
            
            # Handle rate limit errors (429) with retry suggestion
            if "429" in error_msg or "quota" in error_msg.lower():
                logger.error(f"🚫 Rate limit hit for {url}")
                
                # Try to extract retry delay from error message
                import re
                retry_match = re.search(r'retry in (\d+\.?\d*)', error_msg)
                if retry_match:
                    retry_seconds = float(retry_match.group(1))
                    logger.warning(f"   Gemini suggests retrying in {retry_seconds:.1f}s")
                
                return {
                    "url": url,
                    "page_type": "RateLimitError",
                    "error": "Rate limit exceeded - too many requests per minute",
                    "findings": [],
                    "technologies": [],
                    "summary": "Analysis failed: Gemini API rate limit exceeded (10 requests/minute for free tier)",
                    "analyzed_at": datetime.now().isoformat()
                }
            
            # Handle other errors
            logger.error(f"Gemini analysis failed for {url}: {e}")
            return {
                "url": url,
                "page_type": "Error",
                "error": str(e),
                "findings": [],
                "technologies": [],
                "summary": f"Analysis failed: {str(e)}",
                "analyzed_at": datetime.now().isoformat()
            }
    
    async def _store_analysis_to_chromadb(
        self,
        url: str,
        analysis: Dict[str, Any]
    ) -> None:
        """Store Gemini analysis results to ChromaDB with unified v3 schema."""
        try:
            doc_id = self._generate_doc_id(f"{url}_analysis")
            
            # Create searchable document from analysis (new unified schema)
            findings = analysis.get('findings', [])
            findings_str = ', '.join([f"{f.get('id', 'N/A')}: {f.get('vector', 'Unknown')}" for f in findings])
            
            analysis_text = f"""
URL: {url}
Page Type: {analysis.get('page_type', 'Unknown')}
Summary: {analysis.get('summary', '')}
Findings: {findings_str}
Technologies: {', '.join(analysis.get('technologies', []))}
"""
            
            # Build metadata with template-aware fields
            # ChromaDB requires all metadata values to be non-None (str, int, float, or bool)
            metadata = {
                'url': url,
                'page_type': analysis.get('page_type', 'Unknown'),
                'timestamp': analysis.get('analyzed_at', datetime.now().isoformat()),
                'job_id': self.job_id,
                'findings_count': len(findings),
                'analysis_json': json.dumps(analysis),
                'schema_version': 'v3_unified'
            }
            
            # ========== ADD TEMPLATE-AWARE METADATA TO CHROMADB ==========
            # These fields are critical for SecurityTestCore deduplication
            # Only add if NOT None (ChromaDB rejects None values)
            if analysis.get('cluster_id') is not None:
                metadata['cluster_id'] = int(analysis['cluster_id'])
            if analysis.get('template_id'):
                metadata['template_id'] = str(analysis['template_id'])
            if analysis.get('layout_signature'):
                metadata['layout_signature'] = str(analysis['layout_signature'])
            if analysis.get('dom_structure_hash'):
                metadata['dom_structure_hash'] = str(analysis['dom_structure_hash'])
            if analysis.get('is_template_shared') is not None:
                metadata['is_template_shared'] = bool(analysis['is_template_shared'])
            
            self.analysis_collection.add(
                ids=[doc_id],
                documents=[analysis_text],
                metadatas=[metadata]
            )

            
            # ========== ADD FINDINGS TO PERSISTENT MEMORY ==========
            findings = analysis.get('findings', [])
            
            for finding in findings:
                # Create detailed note for each finding
                note = self._create_finding_note_unified(finding, analysis)
                self.add_memory(note, url=url, finding_id=finding.get('id'))
            
            logger.debug(f"✓ Added {len(findings)} findings to memory")
            
            logger.debug(f"✓ Stored analysis to ChromaDB: {url}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis to ChromaDB for {url}: {e}")
    
    def _create_finding_note_unified(self, finding: Dict[str, Any], page_data: Dict[str, Any]) -> str:
        """Create a detailed note for a security finding (unified schema)."""
        note_parts = [
            f"=== Security Finding: {finding.get('id', 'N/A')} ===",
            f"URL: {page_data.get('url', 'N/A')}",
            f"Page Type: {page_data.get('page_type', 'Unknown')}",
            f"Vector: {finding.get('vector', 'Unknown')}",
            f"\nEvidence:",
            f"  {finding.get('evidence', 'N/A')}",
        ]
        
        # Add attack details if present
        if finding.get('method'):
            note_parts.append(f"\nMethod: {finding['method']}")
        if finding.get('parameters'):
            note_parts.append(f"Parameters: {', '.join(finding['parameters'])}")
        if finding.get('payload'):
            note_parts.append(f"Example Payloads:")
            for payload in finding['payload'][:3]:  # Limit to 3 payloads
                note_parts.append(f"  - {payload}")
        
        # Add related endpoints if available
        if finding.get('related_endpoints'):
            note_parts.append(f"\nRelated Endpoints:")
            for endpoint in finding['related_endpoints']:
                note_parts.append(f"  - {endpoint}")
        
        # Add info context for Information Disclosure findings
        if finding.get('info'):
            info = finding['info']
            note_parts.append(f"\nDisclosed Information:")
            note_parts.append(f"  Type: {info.get('type', 'N/A')}")
            note_parts.append(f"  Value: {info.get('value', 'N/A')}")
            note_parts.append(f"  Context: {info.get('context', 'N/A')}")
        
        # Add technologies context
        if page_data.get('technologies'):
            note_parts.append(f"\nTechnologies: {', '.join(page_data['technologies'][:5])}")
        
        # Add metadata
        meta = page_data.get('meta', {})
        if meta:
            note_parts.append(f"\nMetadata:")
            note_parts.append(f"  Analyzed: {meta.get('analyzed_at', 'N/A')}")
            if meta.get('cluster_id') is not None:
                note_parts.append(f"  Cluster: {meta['cluster_id']}")
        
        return '\n'.join(note_parts)

    
    async def analyze_batch(
        self,
        crawl_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze crawled data with AI.
        
        Args:
            crawl_data: List of crawl results from crawler
            
        Returns:
            Dictionary containing analysis results and summary
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"ANALYSIS PHASE")
        logger.info(f"{'='*60}")
        logger.info(f"Analyzing {len(crawl_data)} pages with Gemini...")
        logger.info(f"Analysis mode: {self.analysis_mode}")
        
        # Debug: Check input data
        if not crawl_data:
            logger.error("❌ No crawl data provided to analyzer!")
            return {
                'total_analyzed': 0,
                'analysis_results': [],
                'summary': self._generate_summary(),
                'analysis_mode': self.analysis_mode,
                'chromadb_collection': f"analysised_job_{self.job_id}",
                'json_output_path': str(self.job_record_dir / "analysis_results.json")
            }
        
        # Analyze in batches with timeout protection
        try:
            await self._analyze_data_batch(crawl_data)
                
        except Exception as e:
            logger.error(f"❌ Analysis failed: {e}")
            logger.warning(f"⚠️  Continuing with {len(self.analysis_results)} successful analyses...")
            import traceback
            traceback.print_exc()
        
        # Generate summary
        summary = self._generate_summary()
        
        logger.info(f"\n{'='*60}")
        logger.info(f"ANALYSIS COMPLETE")
        logger.info(f"{'='*60}")
        logger.info(f"  Total analyzed: {len(self.analysis_results)}")
        
        # Save results to JSON file
        json_output_path = self.job_record_dir / "analysis_results.json"
        notes_output_path = self.job_record_dir / "findings_notes.txt"
        
        try:
            # Prepare unified v3 schema format
            json_data = {
                'job_id': self.job_id,
                'total_analyzed': len(self.analysis_results),
                'analysis_mode': self.analysis_mode,
                'schema_version': 'v3_unified',
                'timestamp': datetime.now().isoformat(),
                'analysis_results': self.analysis_results,
                'summary': summary
            }
            
            # Save unified format
            with open(json_output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"  ✅ Analysis results (v3 unified) saved to: {json_output_path}")
            
            # ========== OUTPUT FINDINGS NOTES ==========
            try:
                all_notes = []
                memory_results = self.memory_collection.get()
                
                if memory_results and memory_results.get('documents'):
                    all_notes.extend(memory_results['documents'])
                
                if all_notes:
                    with open(notes_output_path, 'w', encoding='utf-8') as f:
                        f.write(f"{'='*80}\n")
                        f.write(f"SECURITY FINDINGS NOTES - Job: {self.job_id}\n")
                        f.write(f"Generated: {datetime.now().isoformat()}\n")
                        f.write(f"Total Notes: {len(all_notes)}\n")
                        f.write(f"{'='*80}\n\n")
                        
                        for idx, note in enumerate(all_notes, 1):
                            f.write(f"\n{'='*80}\n")
                            f.write(f"Note #{idx}\n")
                            f.write(f"{'='*80}\n")
                            f.write(note)
                            f.write(f"\n\n")
                    
                    logger.info(f"  ✅ Findings notes saved to: {notes_output_path}")
                    logger.info(f"  📝 Total notes: {len(all_notes)}")
                    
                    # Also output notes to console for debugging
                    print(f"\n{'='*80}")
                    print(f"FINDINGS NOTES OUTPUT (for debugging)")
                    print(f"{'='*80}")
                    for idx, note in enumerate(all_notes[:3], 1):  # Show first 3
                        print(f"\n--- Note #{idx} ---")
                        print(note[:500] + "..." if len(note) > 500 else note)
                    
                    if len(all_notes) > 3:
                        print(f"\n... and {len(all_notes) - 3} more notes")
                    print(f"\nFull notes saved to: {notes_output_path}\n")
            
            except Exception as e:
                logger.error(f"  ❌ Failed to save notes output: {e}")
            
        except Exception as e:
            logger.error(f"  ❌ Failed to save JSON output: {e}")
        
        return {
            'total_analyzed': len(self.analysis_results),
            'analysis_results': self.analysis_results,
            'summary': summary,
            'analysis_mode': self.analysis_mode,
            'chromadb_collection': f"analysised_job_{self.job_id}",
            'json_output_path': str(json_output_path)
        }
    
    async def _analyze_data_batch(self, data_batch: List[Dict[str, Any]]) -> None:
        """Analyze crawl data sequentially (no batching) to respect rate limits."""
        
        total_pages = len(data_batch)
        analyzed_count = 0
        
        logger.info(f"Starting sequential analysis of {total_pages} pages...")
        logger.info(f"Estimated time: ~{total_pages * 8} seconds ({total_pages * 8 / 60:.1f} minutes)")
        
        # Process ONE page at a time (completely sequential)
        self.note = []
        for idx, crawl_data in enumerate(data_batch, 1):
            url = crawl_data['url']
            
            try:
                logger.info(f"\n📄 [{idx}/{total_pages}] Analyzing: {url[:70]}...")
                
                # Get content
                content = crawl_data.get('cleaned_text', '') or crawl_data.get('html_content', '')
                markdown = crawl_data.get('markdown_content', '') or content[:8000]
                
                # Analyze ONE page (now synchronous, no timeout wrapper needed)
                analysis = self._analyze_with_gemini(url, content, markdown)
                
                # Store result
                if isinstance(analysis, dict) and analysis:
                    try:
                        await self._store_analysis_to_chromadb(analysis['url'], analysis)
                        self.analysis_results.append(analysis)
                        analyzed_count += 1
                        
                        # Show success with page type
                        page_type = analysis.get('page_type', 'Unknown')
                        findings_count = len(analysis.get('findings', []))
                        logger.info(f"  ✓ Success: {page_type} ({findings_count} findings)")
                        
                    except Exception as e:
                        logger.error(f"  ❌ Failed to store analysis: {e}")
                else:
                    logger.warning(f"  ⚠️  Invalid analysis result")
                    
            except asyncio.TimeoutError:
                logger.error(f"  ⏱️  Analysis timed out after 90s")
                # Create error result
                error_result = {
                    "url": url,
                    "page_type": "Timeout",
                    "error": "Analysis timeout after 90s",
                    "findings": [],
                    "technologies": [],
                    "summary": "Analysis timed out",
                    "analyzed_at": datetime.now().isoformat()
                }
                self.analysis_results.append(error_result)
                
            except Exception as e:
                logger.error(f"  ❌ Analysis error: {e}")
                # Create error result
                error_result = {
                    "url": url,
                    "page_type": "Error",
                    "error": str(e),
                    "findings": [],
                    "technologies": [],
                    "summary": f"Analysis failed: {str(e)}",
                    "analyzed_at": datetime.now().isoformat()
                }
                self.analysis_results.append(error_result)
            
            # Progress update
            if idx < total_pages:
                remaining = total_pages - idx
                eta_seconds = remaining * 8
                logger.info(f"  ⏳ Progress: {idx}/{total_pages} complete, ~{eta_seconds}s remaining ({eta_seconds/60:.1f}m)")
        
        logger.info(f"\n✅ Sequential analysis complete: {analyzed_count}/{total_pages} successful")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary of analysis results."""
        summary = {
            'total_pages': len(self.analysis_results),
            'page_types': {},
            'total_findings': 0,
            'technologies': set(),
        }
        
        for analysis in self.analysis_results:
            # Count page types
            page_type = analysis.get('page_type', 'Unknown')
            summary['page_types'][page_type] = summary['page_types'].get(page_type, 0) + 1
            
            # Count findings (new unified schema)
            summary['total_findings'] += len(analysis.get('findings', []))
            
            # Collect technologies
            summary['technologies'].update(analysis.get('technologies', []))
        
        summary['technologies'] = list(summary['technologies'])
        
        return summary
    
    def query_analysis_results(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Query analysis results from ChromaDB."""
        try:
            results = self.analysis_collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            return [{
                'url': results['metadatas'][0][i]['url'],
                'page_type': results['metadatas'][0][i]['page_type'],
                'analysis': json.loads(results['metadatas'][0][i]['analysis_json']),
                'preview': results['documents'][0][i][:500]
            } for i in range(len(results['ids'][0]))]
            
        except Exception as e:
            logger.error(f"Failed to query analysis results: {e}")
            return []


async def run_analyzer(
    crawl_data: Dict[str, Any],
    gemini_api_key: str,
    analysis_mode: str = "smart",
    max_concurrent: int = 1,  # Changed from 3 to 1 for free tier
    record_dir: str = "./record"
) -> Dict[str, Any]:
    """
    Main function to run the security analyzer.
    
    Args:
        crawl_data: Dictionary with crawl results from crawler.py
        gemini_api_key: Gemini API key for analysis
        analysis_mode: Analysis strategy ("realtime", "batch", "smart")
        max_concurrent: Maximum concurrent analysis operations
        record_dir: Directory to save JSON records
        
    Returns:
        Dictionary with analysis results and summary
    """
    job_id = crawl_data.get('job_id', 'default')
    crawl_results = crawl_data.get('crawl_results', [])
    
    analyzer = SecurityAnalyzer(
        gemini_api_key=gemini_api_key,
        job_id=job_id,
        max_concurrent=max_concurrent,
        analysis_mode=analysis_mode,
        record_dir=record_dir
    )
    
    results = await analyzer.analyze_batch(crawl_results)
    
    return results


# Example integration
if __name__ == "__main__":
    import asyncio
    import sys
    from .crawler import run_crawler
    
    async def main():
        # Configuration
        GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your-api-key-here")
        
        if GEMINI_API_KEY == "your-api-key-here":
            print("❌ Please set GEMINI_API_KEY environment variable")
            sys.exit(1)
        
        print("="*60)
        print("INTEGRATED CRAWL + ANALYSIS WORKFLOW")
        print("="*60)
        
        # Step 1: Crawl websites
        print("\n[STEP 1] Running crawler...")
        crawl_data = await run_crawler(
            urls=["https://example.com"],
            base_domain="example.com",
            job_id="integrated_test",
            max_pages=5
        )
        
        print(f"\n✓ Crawl completed: {crawl_data['total_crawled']} pages")
        
        # Step 2: Analyze crawled data
        print("\n[STEP 2] Running analyzer...")
        analysis_data = await run_analyzer(
            crawl_data=crawl_data,
            gemini_api_key=GEMINI_API_KEY,
            analysis_mode="smart"
        )
        
        print(f"\n✓ Analysis completed: {analysis_data['total_analyzed']} pages")
        
        # Step 3: Display results
        print("\n[STEP 3] Results Summary")
        print("="*60)
        summary = analysis_data['summary']
        print(f"Total pages analyzed: {summary['total_pages']}")
        print(f"Total findings: {summary['total_findings']}")
        
        print(f"\nPage types:")
        for page_type, count in summary['page_types'].items():
            print(f"  {page_type}: {count}")
        
        print(f"\nTechnologies detected:")
        for tech in summary['technologies'][:10]:
            print(f"  - {tech}")
    
    asyncio.run(main())
