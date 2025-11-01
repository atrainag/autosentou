"""
RAG-Enhanced Knowledge Manager
Uses ChromaDB with vector embeddings for intelligent semantic search
instead of basic string matching. Falls back to file-based mode if RAG unavailable.
"""
import json
import os
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import threading

logger = logging.getLogger(__name__)


class KnowledgeManager:
    """
    RAG-powered penetration testing knowledge manager.
    Uses vector embeddings for semantic search of exploits, dorks, and vulnerable paths.
    """

    def __init__(self, knowledge_dir: str = None, persist_dir: str = None):
        if knowledge_dir is None:
            # Default to services/ai/knowledge/
            self.knowledge_dir = Path(__file__).parent / "knowledge"
        else:
            self.knowledge_dir = Path(knowledge_dir)

        if persist_dir is None:
            self.persist_dir = Path(__file__).parent / "databases" / "knowledge_rag"
        else:
            self.persist_dir = Path(persist_dir)

        self.knowledge_dir.mkdir(parents=True, exist_ok=True)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        # RAG components (lazy loaded)
        self._embedding_model = None
        self._chroma_client = None
        self._exploits_collection = None
        self._dorks_collection = None
        self._paths_collection = None
        self._fallback_mode = False
        self._initialized = False
        self._lock = threading.Lock()

        # File-based caches (fallback)
        self._exploits = None
        self._dorks = None
        self._vulnerable_paths = None
        self._execution_stats = {}

        logger.info(f"KnowledgeManager initialized with RAG support")

    def _ensure_initialized(self):
        """Lazy initialization of RAG components."""
        if self._fallback_mode or self._initialized:
            return

        with self._lock:
            if self._fallback_mode or self._initialized:
                return

            try:
                logger.info("Initializing RAG components...")

                # Load embedding model
                if self._embedding_model is None:
                    logger.info("Loading embedding model: all-MiniLM-L6-v2")
                    self._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
                    logger.info("✓ Embedding model loaded")

                # Initialize ChromaDB
                if self._chroma_client is None:
                    logger.info(f"Initializing ChromaDB at: {self.persist_dir}")
                    try:
                        self._chroma_client = chromadb.PersistentClient(
                            path=str(self.persist_dir),
                            settings=Settings(
                                anonymized_telemetry=False,
                                allow_reset=True
                            )
                        )
                        logger.info("✓ ChromaDB persistent client initialized")
                    except Exception as e:
                        logger.warning(f"Persistent client failed, using in-memory: {e}")
                        self._chroma_client = chromadb.Client(
                            settings=Settings(
                                anonymized_telemetry=False,
                                allow_reset=True
                            )
                        )
                        logger.info("✓ ChromaDB in-memory client initialized")

                # Initialize collections
                self._init_collections()
                self._initialized = True
                logger.info("✓ RAG components fully initialized")

            except Exception as e:
                logger.error(f"✗ Failed to initialize RAG: {e}", exc_info=True)
                logger.warning("✓ Falling back to file-based mode")
                self._fallback_mode = True

    def _init_collections(self):
        """Initialize or load ChromaDB collections."""
        try:
            # Exploits collection
            try:
                self._exploits_collection = self._chroma_client.get_collection("exploits")
                logger.info(f"✓ Loaded exploits collection ({self._exploits_collection.count()} items)")
            except:
                self._exploits_collection = self._chroma_client.create_collection(
                    name="exploits",
                    metadata={"description": "Exploit knowledge base"}
                )
                logger.info("✓ Created new exploits collection")
                self._populate_exploits_collection()

            # Dorks collection
            try:
                self._dorks_collection = self._chroma_client.get_collection("dorks")
                logger.info(f"✓ Loaded dorks collection ({self._dorks_collection.count()} items)")
            except:
                self._dorks_collection = self._chroma_client.create_collection(
                    name="dorks",
                    metadata={"description": "Google dorks knowledge base"}
                )
                logger.info("✓ Created new dorks collection")
                self._populate_dorks_collection()

            # Vulnerable paths collection
            try:
                self._paths_collection = self._chroma_client.get_collection("vulnerable_paths")
                logger.info(f"✓ Loaded paths collection ({self._paths_collection.count()} items)")
            except:
                self._paths_collection = self._chroma_client.create_collection(
                    name="vulnerable_paths",
                    metadata={"description": "Vulnerable path patterns"}
                )
                logger.info("✓ Created new paths collection")
                self._populate_paths_collection()

        except Exception as e:
            logger.error(f"Error initializing collections: {e}", exc_info=True)
            raise

    def _populate_exploits_collection(self):
        """Load exploits from JSON and populate ChromaDB collection."""
        exploits = self.load_exploits()
        if not exploits:
            logger.warning("No exploits to populate")
            return

        try:
            ids = []
            documents = []
            metadatas = []

            for exploit in exploits:
                exploit_id = exploit.get('id', exploit.get('cve_id', str(len(ids))))
                ids.append(exploit_id)

                # Create rich document for embedding
                doc = f"""CVE: {exploit.get('cve_id', 'N/A')}
Service: {exploit.get('service', 'unknown')} {', '.join(exploit.get('versions', []))}
OS: {', '.join(exploit.get('os', []))}
Type: {exploit.get('exploit_type', 'unknown')}
Severity: {exploit.get('severity', 'unknown')} (CVSS {exploit.get('cvss_score', 0)})
Description: {exploit.get('description', 'No description')}
Attack Complexity: {exploit.get('attack_complexity', 'unknown')}"""
                documents.append(doc)

                # Prepare metadata (simple types only for ChromaDB)
                meta = {
                    "cve_id": exploit.get('cve_id', ''),
                    "service": exploit.get('service', ''),
                    "versions": json.dumps(exploit.get('versions', [])),
                    "os": json.dumps(exploit.get('os', [])),
                    "severity": exploit.get('severity', 'unknown'),
                    "cvss_score": float(exploit.get('cvss_score', 0)),
                    "exploit_type": exploit.get('exploit_type', 'unknown'),
                    "requires_auth": bool(exploit.get('requires_auth', False)),
                    "attack_complexity": exploit.get('attack_complexity', 'unknown'),
                    "poc_available": bool(exploit.get('poc_available', False)),
                    "exploit_urls": json.dumps(exploit.get('exploit_urls', [])),
                    "poc_commands": json.dumps(exploit.get('poc_commands', [])),
                    "success_indicators": json.dumps(exploit.get('success_indicators', [])),
                    "success_count": int(exploit.get('success_count', 0)),
                    "attempt_count": int(exploit.get('attempt_count', 0)),
                    "exploitdb_id": exploit.get('exploitdb_id', '')
                }
                metadatas.append(meta)

            # Generate embeddings
            embeddings = self._embedding_model.encode(documents).tolist()

            # Add to collection
            self._exploits_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info(f"✓ Populated exploits collection with {len(exploits)} items")

        except Exception as e:
            logger.error(f"Error populating exploits collection: {e}", exc_info=True)

    def _populate_dorks_collection(self):
        """Load dorks from JSON and populate ChromaDB collection."""
        dorks = self.load_dorks()
        if not dorks:
            logger.warning("No dorks to populate")
            return

        try:
            ids = []
            documents = []
            metadatas = []

            for i, dork in enumerate(dorks):
                dork_id = dork.get('id', f"dork_{i}")
                ids.append(dork_id)

                # Create document for embedding
                doc = f"""Category: {dork.get('category', 'unknown')}
Risk: {dork.get('risk', 'unknown')}
Description: {dork.get('description', '')}
Dork: {dork.get('dork', '')}
Purpose: {dork.get('purpose', '')}"""
                documents.append(doc)

                # Metadata
                meta = {
                    "category": dork.get('category', 'unknown'),
                    "risk": dork.get('risk', 'unknown'),
                    "description": dork.get('description', ''),
                    "dork": dork.get('dork', ''),
                    "purpose": dork.get('purpose', '')
                }
                metadatas.append(meta)

            # Generate embeddings
            embeddings = self._embedding_model.encode(documents).tolist()

            # Add to collection
            self._dorks_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info(f"✓ Populated dorks collection with {len(dorks)} items")

        except Exception as e:
            logger.error(f"Error populating dorks collection: {e}", exc_info=True)

    def _populate_paths_collection(self):
        """Load vulnerable paths from JSON and populate ChromaDB collection."""
        paths = self.load_vulnerable_paths()
        if not paths:
            logger.warning("No vulnerable paths to populate")
            return

        try:
            ids = []
            documents = []
            metadatas = []

            for i, path in enumerate(paths):
                path_id = path.get('id', f"path_{i}")
                ids.append(path_id)

                # Create document for embedding
                doc = f"""Pattern: {path.get('pattern', '')}
Category: {path.get('category', 'unknown')}
Risk: {path.get('risk', 'unknown')}
Description: {path.get('description', '')}
Attack Type: {path.get('attack_type', '')}
Testing Method: {path.get('testing_method', '')}"""
                documents.append(doc)

                # Metadata
                meta = {
                    "pattern": path.get('pattern', ''),
                    "category": path.get('category', 'unknown'),
                    "risk": path.get('risk', 'unknown'),
                    "description": path.get('description', ''),
                    "attack_type": path.get('attack_type', ''),
                    "testing_method": path.get('testing_method', '')
                }
                metadatas.append(meta)

            # Generate embeddings
            embeddings = self._embedding_model.encode(documents).tolist()

            # Add to collection
            self._paths_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info(f"✓ Populated paths collection with {len(paths)} items")

        except Exception as e:
            logger.error(f"Error populating paths collection: {e}", exc_info=True)

    def load_exploits(self) -> List[Dict[str, Any]]:
        """Load exploit knowledge"""
        if self._exploits is not None:
            return self._exploits

        try:
            exploits_file = self.knowledge_dir / "exploits.json"
            if not exploits_file.exists():
                logger.warning(f"Exploits file not found: {exploits_file}")
                return []

            with open(exploits_file, 'r') as f:
                data = json.load(f)

            self._exploits = data.get('exploits', [])

            # Load execution stats if available
            stats_file = self.knowledge_dir / "execution_stats.json"
            if stats_file.exists():
                with open(stats_file, 'r') as f:
                    self._execution_stats = json.load(f)
                    # Merge stats into exploits
                    for exploit in self._exploits:
                        exploit_id = exploit['id']
                        if exploit_id in self._execution_stats:
                            exploit['success_count'] = self._execution_stats[exploit_id].get('success_count', 0)
                            exploit['attempt_count'] = self._execution_stats[exploit_id].get('attempt_count', 0)
                        else:
                            exploit['success_count'] = 0
                            exploit['attempt_count'] = 0

            logger.info(f"✓ Loaded {len(self._exploits)} exploits")
            return self._exploits

        except Exception as e:
            logger.error(f"Error loading exploits: {e}", exc_info=True)
            return []

    def load_dorks(self) -> List[Dict[str, Any]]:
        """Load Google dorks"""
        if self._dorks is not None:
            return self._dorks

        try:
            dorks_file = self.knowledge_dir / "google_dorks.json"
            if not dorks_file.exists():
                logger.warning(f"Dorks file not found: {dorks_file}")
                return []

            with open(dorks_file, 'r') as f:
                data = json.load(f)

            self._dorks = data.get('dorks', [])
            logger.info(f"✓ Loaded {len(self._dorks)} Google dorks")
            return self._dorks

        except Exception as e:
            logger.error(f"Error loading dorks: {e}")
            return []

    def load_vulnerable_paths(self) -> List[Dict[str, Any]]:
        """Load vulnerable path patterns"""
        if self._vulnerable_paths is not None:
            return self._vulnerable_paths

        try:
            paths_file = self.knowledge_dir / "vulnerable_paths.json"
            if not paths_file.exists():
                logger.warning(f"Vulnerable paths file not found: {paths_file}")
                return []

            with open(paths_file, 'r') as f:
                data = json.load(f)

            self._vulnerable_paths = data.get('patterns', [])
            logger.info(f"✓ Loaded {len(self._vulnerable_paths)} vulnerable path patterns")
            return self._vulnerable_paths

        except Exception as e:
            logger.error(f"Error loading vulnerable paths: {e}")
            return []

    def find_matching_exploits(
        self,
        service: str,
        version: str = "",
        os: str = "",
        n_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find exploits using RAG semantic search.
        Falls back to string matching if RAG unavailable.
        """
        # Try RAG first
        if not self._fallback_mode:
            try:
                self._ensure_initialized()

                if not self._fallback_mode and self._exploits_collection is not None:
                    return self._find_exploits_rag(service, version, os, n_results)
            except Exception as e:
                logger.warning(f"RAG search failed, falling back to string matching: {e}")
                self._fallback_mode = True

        # Fallback to original string matching
        return self._find_exploits_fallback(service, version, os, n_results)

    def _find_exploits_rag(
        self,
        service: str,
        version: str,
        os: str,
        n_results: int
    ) -> List[Dict[str, Any]]:
        """RAG-based semantic search for exploits."""
        # Build semantic query
        query_parts = [f"Service: {service}"]
        if version:
            query_parts.append(f"Version: {version}")
        if os:
            query_parts.append(f"Operating System: {os}")

        query = "\n".join(query_parts)
        logger.info(f"RAG search for exploits: {query}")

        # Generate query embedding
        query_embedding = self._embedding_model.encode([query])[0].tolist()

        # Query ChromaDB
        results = self._exploits_collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results * 2  # Get more results for filtering
        )

        # Parse results
        exploits = []
        if results and results['ids']:
            for i in range(len(results['ids'][0])):
                metadata = results['metadatas'][0][i]

                exploit = {
                    'id': results['ids'][0][i],
                    'cve_id': metadata['cve_id'],
                    'service': metadata['service'],
                    'versions': json.loads(metadata['versions']),
                    'os': json.loads(metadata['os']),
                    'severity': metadata['severity'],
                    'cvss_score': metadata['cvss_score'],
                    'exploit_type': metadata['exploit_type'],
                    'requires_auth': metadata['requires_auth'],
                    'attack_complexity': metadata['attack_complexity'],
                    'poc_available': metadata['poc_available'],
                    'exploit_urls': json.loads(metadata['exploit_urls']),
                    'poc_commands': json.loads(metadata['poc_commands']),
                    'success_indicators': json.loads(metadata['success_indicators']),
                    'success_count': metadata['success_count'],
                    'attempt_count': metadata['attempt_count'],
                    'exploitdb_id': metadata.get('exploitdb_id', ''),
                    'description': results['documents'][0][i],
                    'similarity_score': 1 - results['distances'][0][i] if 'distances' in results else 0.5
                }

                # Check version compatibility
                if version and exploit['versions']:
                    version_match = any(
                        version.lower() in v.lower() or v.lower() in version.lower()
                        for v in exploit['versions']
                    )
                    exploit['version_match'] = version_match
                else:
                    exploit['version_match'] = False

                # Check OS compatibility
                if os and exploit['os']:
                    os_match = any(
                        os.lower() in o.lower() or o.lower() in os.lower()
                        for o in exploit['os']
                    )
                    exploit['os_match'] = os_match
                else:
                    exploit['os_match'] = True

                exploits.append(exploit)

        # Rank exploits by relevance
        def exploit_score(exp):
            score = 0
            # Version match is most important
            if exp.get('version_match'):
                score += 100
            # OS match is second most important
            if exp.get('os_match'):
                score += 50
            # Semantic similarity
            score += exp.get('similarity_score', 0) * 30
            # Historical success rate
            if exp['attempt_count'] > 0:
                success_rate = exp['success_count'] / exp['attempt_count']
                score += success_rate * 20
            # Severity bonus
            severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
            score += severity_scores.get(exp.get('severity', 'low'), 0)
            return score

        exploits.sort(key=exploit_score, reverse=True)

        logger.info(f"✓ RAG found {len(exploits)} matching exploits")
        return exploits[:n_results]

    def _find_exploits_fallback(
        self,
        service: str,
        version: str,
        os: str,
        n_results: int
    ) -> List[Dict[str, Any]]:
        """Fallback string-based matching when RAG unavailable."""
        exploits = self.load_exploits()
        matches = []

        service_lower = service.lower()
        version_lower = version.lower()
        os_lower = os.lower()

        for exploit in exploits:
            score = 0

            # Check service match
            exploit_service = exploit.get('service', '').lower()
            if service_lower in exploit_service or exploit_service in service_lower:
                score += 100

            # Check version match
            if version:
                for v in exploit.get('versions', []):
                    if version_lower in v.lower() or v.lower() in version_lower:
                        score += 100
                        exploit['version_match'] = True
                        break
                else:
                    exploit['version_match'] = False
            else:
                exploit['version_match'] = False

            # Check OS match
            if os:
                for o in exploit.get('os', []):
                    if os_lower in o.lower() or o.lower() in os_lower:
                        score += 50
                        exploit['os_match'] = True
                        break
                else:
                    exploit['os_match'] = False
            else:
                exploit['os_match'] = True

            # Add success rate bonus
            if exploit.get('attempt_count', 0) > 0:
                success_rate = exploit.get('success_count', 0) / exploit['attempt_count']
                score += success_rate * 30

            if score > 0:
                exploit['match_score'] = score
                matches.append(exploit.copy())

        # Sort by score
        matches.sort(key=lambda x: x.get('match_score', 0), reverse=True)

        return matches[:n_results]

    def get_relevant_dorks(
        self,
        target: str,
        context: Optional[str] = None,
        categories: Optional[List[str]] = None,
        max_dorks: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get relevant Google dorks using RAG semantic search.
        Falls back to category filtering if RAG unavailable.
        """
        # Try RAG first
        if not self._fallback_mode:
            try:
                self._ensure_initialized()

                if not self._fallback_mode and self._dorks_collection is not None:
                    return self._get_dorks_rag(target, context, categories, max_dorks)
            except Exception as e:
                logger.warning(f"RAG dork search failed, falling back: {e}")
                self._fallback_mode = True

        # Fallback to original filtering
        return self._get_dorks_fallback(target, context, categories, max_dorks)

    def _get_dorks_rag(
        self,
        target: str,
        context: Optional[str],
        categories: Optional[List[str]],
        max_dorks: int
    ) -> List[Dict[str, Any]]:
        """RAG-based semantic search for dorks."""
        # Build semantic query
        query_parts = [f"Target: {target}"]
        if context:
            query_parts.append(f"Context: {context}")
        if categories:
            query_parts.append(f"Categories: {', '.join(categories)}")

        query = "\n".join(query_parts)
        logger.info(f"RAG search for dorks: {query}")

        # Generate query embedding
        query_embedding = self._embedding_model.encode([query])[0].tolist()

        # Build where filter for categories if specified
        where_filter = None
        if categories:
            where_filter = {"category": {"$in": categories}}

        # Query ChromaDB
        results = self._dorks_collection.query(
            query_embeddings=[query_embedding],
            n_results=max_dorks * 2,
            where=where_filter
        )

        # Parse results
        dorks = []
        if results and results['ids']:
            for i in range(len(results['ids'][0])):
                metadata = results['metadatas'][0][i]

                dork_text = metadata['dork'].replace('{target}', target)

                dork = {
                    'id': results['ids'][0][i],
                    'category': metadata['category'],
                    'risk': metadata['risk'],
                    'description': metadata['description'],
                    'dork': dork_text,
                    'purpose': metadata.get('purpose', ''),
                    'similarity_score': 1 - results['distances'][0][i] if 'distances' in results else 0.5
                }
                dorks.append(dork)

        # Sort by risk and similarity
        risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        dorks.sort(
            key=lambda x: (
                risk_priority.get(x.get('risk', 'low'), 0),
                x.get('similarity_score', 0)
            ),
            reverse=True
        )

        logger.info(f"✓ RAG found {len(dorks)} relevant dorks")
        return dorks[:max_dorks]

    def _get_dorks_fallback(
        self,
        target: str,
        context: Optional[str],
        categories: Optional[List[str]],
        max_dorks: int
    ) -> List[Dict[str, Any]]:
        """Fallback category filtering when RAG unavailable."""
        all_dorks = self.load_dorks()
        selected = []

        for dork in all_dorks:
            # Filter by category if specified
            if categories and dork.get('category') not in categories:
                continue

            # Replace {target} placeholder
            dork_text = dork.get('dork', '').replace('{target}', target)
            dork['dork'] = dork_text

            selected.append(dork.copy())

            if len(selected) >= max_dorks:
                break

        # Prioritize by risk
        risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        selected.sort(key=lambda x: risk_priority.get(x.get('risk', 'low'), 0), reverse=True)

        return selected[:max_dorks]

    def get_vulnerable_path_patterns(self, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get vulnerable path patterns.
        """
        patterns = self.load_vulnerable_paths()

        if categories:
            patterns = [p for p in patterns if p.get('category') in categories]

        return patterns

    def check_path_vulnerability(self, path: str) -> List[Dict[str, Any]]:
        """
        Check if a path matches known vulnerable patterns using RAG.
        Falls back to string matching if RAG unavailable.
        """
        # Try RAG first
        if not self._fallback_mode:
            try:
                self._ensure_initialized()

                if not self._fallback_mode and self._paths_collection is not None:
                    return self._check_path_rag(path)
            except Exception as e:
                logger.warning(f"RAG path check failed, falling back: {e}")
                self._fallback_mode = True

        # Fallback to original string matching
        return self._check_path_fallback(path)

    def _check_path_rag(self, path: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """RAG-based semantic path vulnerability check."""
        query = f"Vulnerable path: {path}"
        logger.info(f"RAG path vulnerability check: {path}")

        # Generate query embedding
        query_embedding = self._embedding_model.encode([query])[0].tolist()

        # Query ChromaDB
        results = self._paths_collection.query(
            query_embeddings=[query_embedding],
            n_results=max_results
        )

        # Parse results
        matches = []
        if results and results['ids']:
            for i in range(len(results['ids'][0])):
                metadata = results['metadatas'][0][i]

                # Check if pattern actually matches the path
                pattern_text = metadata['pattern'].lower()
                path_lower = path.lower()

                # Only include if there's actual string overlap or high similarity
                similarity = 1 - results['distances'][0][i] if 'distances' in results else 0.5

                if pattern_text in path_lower or similarity > 0.7:
                    match = {
                        'id': results['ids'][0][i],
                        'pattern': metadata['pattern'],
                        'category': metadata['category'],
                        'risk': metadata['risk'],
                        'description': metadata['description'],
                        'attack_type': metadata.get('attack_type', ''),
                        'testing_method': metadata.get('testing_method', ''),
                        'similarity_score': similarity
                    }
                    matches.append(match)

        # Sort by risk and similarity
        risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        matches.sort(
            key=lambda x: (
                risk_priority.get(x.get('risk', 'low'), 0),
                x.get('similarity_score', 0)
            ),
            reverse=True
        )

        logger.info(f"✓ RAG found {len(matches)} vulnerable path patterns")
        return matches

    def _check_path_fallback(self, path: str) -> List[Dict[str, Any]]:
        """Fallback string matching for path vulnerability check."""
        patterns = self.load_vulnerable_paths()
        matches = []

        path_lower = path.lower()

        for pattern in patterns:
            pattern_text = pattern.get('pattern', '').lower()

            if pattern_text in path_lower:
                matches.append(pattern.copy())

        # Sort by risk
        risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        matches.sort(key=lambda x: risk_priority.get(x.get('risk', 'low'), 0), reverse=True)

        return matches

    def record_exploit_attempt(
        self,
        exploit_id: str,
        target: str,
        success: bool,
        execution_details: Dict[str, Any]
    ):
        """
        Record exploit execution result.
        Updates both RAG collection and execution_stats.json file.
        """
        try:
            # Update file-based stats (always, for fallback)
            stats_file = self.knowledge_dir / "execution_stats.json"
            if stats_file.exists():
                with open(stats_file, 'r') as f:
                    stats = json.load(f)
            else:
                stats = {}

            # Update stats
            if exploit_id not in stats:
                stats[exploit_id] = {
                    'success_count': 0,
                    'attempt_count': 0,
                    'last_attempts': []
                }

            stats[exploit_id]['attempt_count'] += 1
            if success:
                stats[exploit_id]['success_count'] += 1

            # Store last 10 attempts
            attempt_record = {
                'target': target,
                'success': success,
                'timestamp': execution_details.get('timestamp', ''),
                'details': execution_details
            }

            stats[exploit_id]['last_attempts'].append(attempt_record)
            stats[exploit_id]['last_attempts'] = stats[exploit_id]['last_attempts'][-10:]

            # Save stats
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)

            # Update cache
            self._execution_stats = stats

            success_rate = (stats[exploit_id]['success_count'] / stats[exploit_id]['attempt_count'] * 100)
            logger.info(f"✓ Recorded: {exploit_id} | Success: {success} | Rate: {success_rate:.1f}%")

            # Update RAG collection if available
            if not self._fallback_mode:
                try:
                    self._ensure_initialized()
                    if self._exploits_collection is not None:
                        self._update_exploit_stats_rag(exploit_id, success)
                except Exception as e:
                    logger.warning(f"Failed to update RAG stats: {e}")

        except Exception as e:
            logger.error(f"Error recording exploit attempt: {e}")

    def _update_exploit_stats_rag(self, exploit_id: str, success: bool):
        """Update exploit success statistics in RAG collection."""
        try:
            # Get current exploit data
            result = self._exploits_collection.get(ids=[exploit_id])

            if result and result['ids']:
                metadata = result['metadatas'][0]

                # Update counters
                attempt_count = metadata.get('attempt_count', 0) + 1
                success_count = metadata.get('success_count', 0)
                if success:
                    success_count += 1

                # Update metadata
                metadata['attempt_count'] = attempt_count
                metadata['success_count'] = success_count

                # Update in ChromaDB
                self._exploits_collection.update(
                    ids=[exploit_id],
                    metadatas=[metadata]
                )

                success_rate = (success_count / attempt_count * 100) if attempt_count > 0 else 0
                logger.info(f"✓ Updated RAG stats for {exploit_id} | Success Rate: {success_rate:.1f}%")

        except Exception as e:
            logger.error(f"Error updating RAG exploit stats: {e}")

    def add_custom_exploit(self, exploit_data: Dict[str, Any], added_by: str = "user") -> bool:
        """
        Add custom exploit to knowledge base.
        Appends to both exploits.json file and RAG collection.
        """
        try:
            exploits_file = self.knowledge_dir / "exploits.json"

            # Load existing
            if exploits_file.exists():
                with open(exploits_file, 'r') as f:
                    data = json.load(f)
            else:
                data = {
                    "knowledge_type": "exploits",
                    "version": "1.0",
                    "last_updated": "",
                    "description": "CVE exploits and PoC information",
                    "exploits": []
                }

            # Validate
            required = ['cve_id', 'service', 'versions', 'os', 'description']
            for field in required:
                if field not in exploit_data:
                    raise ValueError(f"Missing required field: {field}")

            # Add metadata
            exploit_id = exploit_data.get('id', exploit_data['cve_id'])
            exploit_data['id'] = exploit_id
            exploit_data['added_by'] = added_by
            from datetime import datetime
            exploit_data['added_at'] = datetime.now().isoformat()

            # Add to list
            data['exploits'].append(exploit_data)
            data['last_updated'] = datetime.now().isoformat()

            # Save
            with open(exploits_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Clear cache
            self._exploits = None

            logger.info(f"✓ Added custom exploit to file: {exploit_id}")

            # Add to RAG collection if available
            if not self._fallback_mode:
                try:
                    self._ensure_initialized()
                    if self._exploits_collection is not None:
                        self._add_exploit_to_rag(exploit_data)
                except Exception as e:
                    logger.warning(f"Failed to add exploit to RAG: {e}")

            return True

        except Exception as e:
            logger.error(f"Error adding custom exploit: {e}")
            return False

    def _add_exploit_to_rag(self, exploit_data: Dict[str, Any]):
        """Add exploit to RAG collection."""
        try:
            exploit_id = exploit_data.get('id', exploit_data.get('cve_id'))

            # Create rich document for embedding
            doc = f"""CVE: {exploit_data.get('cve_id', 'N/A')}
Service: {exploit_data.get('service', 'unknown')} {', '.join(exploit_data.get('versions', []))}
OS: {', '.join(exploit_data.get('os', []))}
Type: {exploit_data.get('exploit_type', 'unknown')}
Severity: {exploit_data.get('severity', 'unknown')} (CVSS {exploit_data.get('cvss_score', 0)})
Description: {exploit_data.get('description', 'No description')}
Attack Complexity: {exploit_data.get('attack_complexity', 'unknown')}
Added by: {exploit_data.get('added_by', 'user')}"""

            # Prepare metadata
            meta = {
                "cve_id": exploit_data.get('cve_id', ''),
                "service": exploit_data.get('service', ''),
                "versions": json.dumps(exploit_data.get('versions', [])),
                "os": json.dumps(exploit_data.get('os', [])),
                "severity": exploit_data.get('severity', 'unknown'),
                "cvss_score": float(exploit_data.get('cvss_score', 0)),
                "exploit_type": exploit_data.get('exploit_type', 'unknown'),
                "requires_auth": bool(exploit_data.get('requires_auth', False)),
                "attack_complexity": exploit_data.get('attack_complexity', 'unknown'),
                "poc_available": bool(exploit_data.get('poc_available', False)),
                "exploit_urls": json.dumps(exploit_data.get('exploit_urls', [])),
                "poc_commands": json.dumps(exploit_data.get('poc_commands', [])),
                "success_indicators": json.dumps(exploit_data.get('success_indicators', [])),
                "success_count": 0,
                "attempt_count": 0,
                "exploitdb_id": exploit_data.get('exploitdb_id', '')
            }

            # Generate embedding
            embedding = self._embedding_model.encode([doc])[0].tolist()

            # Add to collection
            self._exploits_collection.add(
                ids=[exploit_id],
                documents=[doc],
                metadatas=[meta],
                embeddings=[embedding]
            )

            logger.info(f"✓ Added custom exploit to RAG: {exploit_id}")

        except Exception as e:
            logger.error(f"Error adding exploit to RAG: {e}")

    def add_custom_dork(self, dork_data: Dict[str, Any], added_by: str = "user") -> bool:
        """
        Add custom Google dork to knowledge base.
        """
        try:
            dorks_file = self.knowledge_dir / "google_dorks.json"

            # Load existing
            if dorks_file.exists():
                with open(dorks_file, 'r') as f:
                    data = json.load(f)
            else:
                data = {
                    "knowledge_type": "google_dorks",
                    "version": "1.0",
                    "last_updated": "",
                    "description": "Google dorks for web reconnaissance",
                    "dorks": []
                }

            # Validate
            required = ['dork', 'category', 'description', 'risk']
            for field in required:
                if field not in dork_data:
                    raise ValueError(f"Missing required field: {field}")

            # Add metadata
            dork_data['id'] = dork_data.get('id', f"custom_{len(data['dorks'])}")
            dork_data['added_by'] = added_by

            # Add to list
            data['dorks'].append(dork_data)
            data['last_updated'] = str(Path(dorks_file).stat().st_mtime)

            # Save
            with open(dorks_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Clear cache
            self._dorks = None

            logger.info(f"✓ Added custom dork: {dork_data['id']}")
            return True

        except Exception as e:
            logger.error(f"Error adding custom dork: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics including RAG status"""
        exploits = self.load_exploits()
        dorks = self.load_dorks()
        paths = self.load_vulnerable_paths()

        total_attempts = sum(e.get('attempt_count', 0) for e in exploits)
        total_successes = sum(e.get('success_count', 0) for e in exploits)
        success_rate = (total_successes / total_attempts * 100) if total_attempts > 0 else 0

        stats = {
            'mode': 'fallback' if self._fallback_mode else 'rag',
            'rag_initialized': self._initialized,
            'total_exploits': len(exploits),
            'total_dorks': len(dorks),
            'total_vulnerable_patterns': len(paths),
            'total_exploit_attempts': total_attempts,
            'total_successes': total_successes,
            'overall_success_rate': round(success_rate, 2),
            'knowledge_directory': str(self.knowledge_dir)
        }

        # Add RAG collection stats if available
        if self._initialized and not self._fallback_mode:
            try:
                if self._exploits_collection is not None:
                    stats['rag_exploits_count'] = self._exploits_collection.count()
                if self._dorks_collection is not None:
                    stats['rag_dorks_count'] = self._dorks_collection.count()
                if self._paths_collection is not None:
                    stats['rag_paths_count'] = self._paths_collection.count()
                stats['rag_persist_directory'] = str(self.persist_dir)
            except Exception as e:
                logger.warning(f"Error getting RAG stats: {e}")

        return stats


# Global instance
_knowledge_manager = None


def get_knowledge_manager():
    """Get KnowledgeManager singleton"""
    global _knowledge_manager
    if _knowledge_manager is None:
        _knowledge_manager = KnowledgeManager()
    return _knowledge_manager
