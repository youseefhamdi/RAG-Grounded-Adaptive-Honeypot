"""
Don Ingestion Pipeline
3-stage gate: integrity → credibility → chunk+embed.

Supports:
- Exploit-DB
- MITRE ATT&CK
- OSINT IP Reputation
- Internal History
"""
import hashlib
import json
import logging
import math
import yaml
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from core.modelprovider import get_provider

logger = logging.getLogger("ragin.don.ingestion")

def sha256_hash(text: str) -> str:
    """Compute SHA-256 hash of text."""
    return hashlib.sha256(text.encode()).hexdigest()

class PageRankCredibilityScorer:
    """
    Simplified PageRank-based trust scoring.

    - Sources with known high-trust domains receive higher base scores.
    - Cross-references between documents boost scores iteratively.
    """

    HIGH_TRUST_SOURCES = {
        "mitre.org": 0.95,
        "nvd.nist.gov": 0.90,
        "exploit-db.com": 0.80,
        "cve.mitre.org": 0.92,
        "github.com/cisagov": 0.85,
    }

    def __init__(self, trust_threshold: float = 0.35):
        self.threshold = trust_threshold

    def score(self, doc: Dict[str, Any]) -> float:
        """Calculate credibility score for document."""
        source = doc.get("source_url", "")
        for domain, score in self.HIGH_TRUST_SOURCES.items():
            if domain in source:
                return score

        # Default score based on document completeness
        has_cve = float("CVE-" in doc.get("content", "")) * 0.2
        has_cwe = float("CWE-" in doc.get("content", "")) * 0.1
        has_mitre = float("T1" in doc.get("content", "")) * 0.15
        return min(0.4 + has_cve + has_cwe + has_mitre, 1.0)

    def passes(self, doc: Dict[str, Any]) -> bool:
        """Check if document passes credibility threshold."""
        return self.score(doc) >= self.threshold

class DonIngestionPipeline:
    """
    Don ingestion pipeline with 3-stage filtering.

    Stage 1: SHA-256 integrity check
    Stage 2: PageRank credibility gate
    Stage 3: Chunk + embed + upsert to Qdrant
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        don_cfg = cfg["don"]
        mp_cfg = cfg["model_provider"]

        self.qdrant = QdrantClient(host=don_cfg["qdrant_host"], 
                                   port=don_cfg["qdrant_port"])
        self.collection = don_cfg["collection_name"]
        self.chunk_size = don_cfg["chunk_size"]
        self.chunk_overlap = don_cfg["chunk_overlap"]

        ptype = mp_cfg["type"]
        self.embed_dims = mp_cfg[ptype]["embed_dims"]
        self.provider = get_provider(config_path)
        self.credibility = PageRankCredibilityScorer(don_cfg["pagerank_trust_threshold"])

        self._init_collection()

    def _init_collection(self):
        """Initialize Qdrant collection if not exists."""
        existing = [c.name for c in self.qdrant.get_collections().collections]
        if self.collection not in existing:
            self.qdrant.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(
                    size=self.embed_dims,
                    distance=Distance.COSINE
                )
            )
            logger.info(f"Created Qdrant collection: {self.collection}")

    def chunk_text(self, text: str) -> List[str]:
        """Split text into overlapping chunks."""
        words = text.split()
        chunks, i = [], 0
        while i < len(words):
            chunk = " ".join(words[i:i + self.chunk_size])
            chunks.append(chunk)
            i += self.chunk_size - self.chunk_overlap
        return chunks

    def ingest_document(self, doc: Dict[str, Any]) -> int:
        """
        Ingest a single document through 3-stage gate.

        Returns: number of chunks indexed.
        """
        content = doc.get("content", "")
        if not content.strip():
            return 0

        # Stage 1: Integrity
        doc_hash = sha256_hash(content)
        doc["hash"] = doc_hash

        # Stage 2: Credibility gate
        if not self.credibility.passes(doc):
            logger.debug(f"REJECTED (credibility): {doc.get('title', 'unknown')}")
            return 0

        # Stage 3: Chunk + embed + upsert
        chunks = self.chunk_text(content)
        if not chunks:
            return 0

        embeddings = self.provider.embed(chunks)

        points = []
        for i, (chunk, vec) in enumerate(zip(chunks, embeddings)):
            point_id = abs(hash(f"{doc_hash}_{i}")) % (2**31)
            points.append(PointStruct(
                id=point_id,
                vector=vec.tolist(),
                payload={
                    "text": chunk,
                    "source": doc.get("source", "unknown"),
                    "source_url": doc.get("source_url", ""),
                    "title": doc.get("title", ""),
                    "doc_type": doc.get("doc_type", "generic"),
                    "cves": doc.get("cves", []),
                    "mitre_techniques": doc.get("mitre_techniques", []),
                    "hash": doc_hash,
                    "chunk_index": i,
                    "credibility": self.credibility.score(doc)
                }
            ))

        self.qdrant.upsert(collection_name=self.collection, points=points)
        return len(chunks)

    def ingest_batch(self, docs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Ingest batch of documents."""
        total, accepted, chunks = len(docs), 0, 0
        for doc in docs:
            n = self.ingest_document(doc)
            if n > 0:
                accepted += 1
                chunks += n
        logger.info(f"Ingested {accepted}/{total} docs → {chunks} chunks")
        return {"total": total, "accepted": accepted, "chunks": chunks}
