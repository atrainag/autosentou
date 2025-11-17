"""
RAG Service for Knowledge Base Vulnerability Management (OWASP Patterns)
Handles ONLY OWASP Top 10 vulnerability patterns - NOT CVE data!
CVE lookups are done via API searches (ExploitDB, GitHub, Google).
"""
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional
import os
import threading
import logging
from services.ai.config import ai_config

logger = logging.getLogger(__name__)


class KnowledgeBaseRAGService:
    """
    RAG service for OWASP vulnerability pattern matching.

    This is ONLY for dynamic OWASP Top 10 patterns that aren't documented as CVEs.
    CVE data is fetched from APIs (ExploitDB, GitHub, Google) - NOT stored locally.
    """

    _instance = None
    _lock = threading.Lock()
    _initialized = False

    def __new__(cls, *args, **kwargs):
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        persist_directory: str = "./services/ai/databases/knowledge_rag",
        collection_name: str = "knowledge_base_vulnerabilities",
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

            # Lazy initialization
            self.embedding_model = None
            self.client = None
            self.collection = None
            self.fallback_mode = False

            self._initialized = True
            logger.info("KnowledgeBaseRAGService initialized (for OWASP patterns only)")

    def _ensure_initialized(self):
        """Lazy initialization of heavy components."""
        if self.fallback_mode:
            return

        if self.client is not None and self.embedding_model is not None:
            return

        with self._lock:
            if self.fallback_mode or (self.client is not None and self.embedding_model is not None):
                return

            try:
                # Initialize embedding model
                if self.embedding_model is None:
                    logger.info(f"Loading embedding model: {self.embedding_model_name}")
                    self.embedding_model = SentenceTransformer(self.embedding_model_name)
                    logger.info("✓ Embedding model loaded")

                # Initialize ChromaDB
                if self.client is None:
                    logger.info(f"Initializing ChromaDB at: {self.persist_directory}")
                    os.makedirs(self.persist_directory, exist_ok=True)

                    try:
                        self.client = chromadb.PersistentClient(
                            path=self.persist_directory,
                            settings=Settings(
                                anonymized_telemetry=False,
                                allow_reset=True
                            )
                        )
                    except Exception as e:
                        logger.warning(f"PersistentClient failed, using in-memory: {e}")
                        self.client = chromadb.Client(
                            settings=Settings(anonymized_telemetry=False)
                        )

                    # Get or create collection
                    self.collection = self.client.get_or_create_collection(
                        name=self.collection_name,
                        metadata={"description": "OWASP vulnerability patterns for intelligent matching"}
                    )

                    logger.info(f"✓ ChromaDB collection ready: {self.collection_name}")

            except Exception as e:
                logger.error(f"Failed to initialize RAG service: {e}", exc_info=True)
                self.fallback_mode = True


# ========== KB Vulnerability RAG Functions ==========
# These functions manage OWASP vulnerability patterns in RAG


def add_kb_vulnerability_to_rag(kb_vulnerability):
    """
    Add a knowledge base vulnerability (OWASP pattern) to RAG for intelligent matching.

    Args:
        kb_vulnerability: KnowledgeBaseVulnerability model instance
    """
    try:
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
    Search for similar OWASP vulnerability patterns in the knowledge base using RAG.

    Args:
        query_text: The text to search for (finding description/title)
        top_k: Number of results to return

    Returns:
        List of matching KB entries with similarity scores
    """
    try:
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
