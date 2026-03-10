"""
Don RAG Engine
Hybrid dense+sparse retrieval → LLM-grounded enrichment.

Produces:
- CVE mappings
- MITRE ATT&CK techniques
- Evidence citations
- IQS (Intelligence Quality Score)
"""
import re
import json
import yaml
import logging
import numpy as np
from typing import List, Dict, Any, Tuple
from qdrant_client import QdrantClient
from core.modelprovider import get_provider

logger = logging.getLogger("ragin.don")

# BM25 Sparse Retrieval (lightweight, no external dependency)
class BM25:
    """Simple BM25 implementation for sparse retrieval."""

    def __init__(self, corpus: List[str], k1: float = 1.5, b: float = 0.75):
        import math
        from collections import Counter
        self.k1, self.b = k1, b
        self.corpus = corpus
        self.doc_freqs = []
        self.idf = {}
        self.avgdl = 0

        df: Dict[str, int] = {}
        for doc in corpus:
            tokens = set(doc.lower().split())
            self.doc_freqs.append(Counter(doc.lower().split()))
            for t in tokens:
                df[t] = df.get(t, 0) + 1

        N = len(corpus)
        self.avgdl = sum(len(d.split()) for d in corpus) / max(N, 1)
        self.idf = {t: math.log((N - f + 0.5) / (f + 0.5) + 1) 
                   for t, f in df.items()}

    def score(self, query: str, doc_idx: int) -> float:
        """Score a document for given query."""
        tokens = query.lower().split()
        dl = sum(self.doc_freqs[doc_idx].values())
        score = 0.0
        for t in tokens:
            if t not in self.idf:
                continue
            f = self.doc_freqs[doc_idx].get(t, 0)
            score += self.idf[t] * (f * (self.k1 + 1)) / \
                    (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return score

    def get_top_k(self, query: str, k: int = 3) -> List[Tuple[int, float]]:
        """Get top-k documents for query."""
        scores = [(i, self.score(query, i)) for i in range(len(self.corpus))]
        return sorted(scores, key=lambda x: x[1], reverse=True)[:k]

class DonRAGEngine:
    """
    Don hybrid RAG engine.

    Combines dense (Qdrant) and sparse (BM25) retrieval,
    then uses LLM for grounded threat analysis.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        don_cfg = cfg["don"]
        self.qdrant = QdrantClient(host=don_cfg["qdrant_host"], 
                                   port=don_cfg["qdrant_port"])
        self.collection = don_cfg["collection_name"]
        self.top_k = don_cfg["top_k"]
        self.alpha = don_cfg["dense_weight"]  # 0.7
        self.beta = don_cfg["sparse_weight"]   # 0.3

        self.provider = get_provider(config_path)
        self.bm25_cache: Dict[str, BM25] = {}

    def build_query(self, session: dict) -> str:
        """Build search query from session data."""
        cmds = " ".join(session.get("commands", [])[:20])
        files = " ".join(session.get("files", [])[:10])
        src = session.get("srcip", "")
        return f"{cmds} {files} {src}".strip()

    def dense_search(self, query_vec: np.ndarray, k: int) -> List[Dict]:
        """Dense vector search using Qdrant."""
        results = self.qdrant.search(
            collection_name=self.collection,
            query_vector=query_vec.tolist(),
            limit=k,
            with_payload=True
        )
        return [{"text": r.payload["text"], 
                "payload": r.payload, 
                "dense_score": r.score} for r in results]

    def sparse_search(self, query: str, dense_results: List[Dict], k: int) -> List[Dict]:
        """BM25 sparse search over dense candidates for re-ranking."""
        corpus = [d["text"] for d in dense_results]
        if not corpus:
            return []

        bm25 = BM25(corpus)
        top = bm25.get_top_k(query, k=min(k, len(corpus)))
        return [{"text": dense_results[i]["text"], 
                "payload": dense_results[i]["payload"],
                "sparse_score": s} for i, s in top]

    def retrieve(self, session: dict) -> List[Dict]:
        """Hybrid dense+sparse retrieval → top-K ranked documents."""
        query = self.build_query(session)
        query_vec = self.provider.embed([query])[0]

        # Dense retrieval
        dense_k = max(int(self.top_k * 0.7), 1)
        sparse_k = self.top_k - dense_k

        dense_docs = self.dense_search(query_vec, k=self.top_k * 2)
        sparse_docs = self.sparse_search(query, dense_docs, k=sparse_k)

        # Fuse scores
        doc_scores: Dict[str, float] = {}
        doc_map: Dict[str, Dict] = {}

        max_dense = max([d["dense_score"] for d in dense_docs], default=1.0)
        for d in dense_docs:
            key = d["text"][:64]
            doc_scores[key] = doc_scores.get(key, 0) + \
                             self.alpha * (d["dense_score"] / max(max_dense, 1e-9))
            doc_map[key] = d

        max_sparse = max([d["sparse_score"] for d in sparse_docs], default=1.0)
        for d in sparse_docs:
            key = d["text"][:64]
            doc_scores[key] = doc_scores.get(key, 0) + \
                             self.beta * (d["sparse_score"] / max(max_sparse, 1e-9))
            doc_map[key] = d

        ranked = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)
        return [doc_map[k] for k, _ in ranked[:self.top_k]]

    def enrich(self, session: dict) -> Dict[str, Any]:
        """
        Full enrichment pipeline:
        1. Retrieve top-K documents
        2. Extract CVEs + MITRE techniques
        3. LLM-grounded analysis
        4. Compute IQS
        """
        docs = self.retrieve(session)

        # Build context
        context = "\n".join([
            f"[DOC {i+1}] Source: {d['payload'].get('source','?')} | "
            f"Title: {d['payload'].get('title','?')}\n{d['text']}"
            for i, d in enumerate(docs)
        ])

        # Extract CVEs and MITRE from retrieved docs
        all_text = " ".join([d["text"] for d in docs])
        cves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", all_text)))
        ttp_ids = list(set(re.findall(r"T\d{4}?\.\d{3}?", all_text)))

        # LLM analysis
        system_prompt = """You are a cyber threat analyst. Analyze the honeypot session ONLY using the provided documents. NEVER assert TTPs or CVEs not supported by the documents. Cite [DOC N] for every claim."""

        user_prompt = f"""Session data:
- Source IP: {session.get('srcip','unknown')}
- Commands: {session.get('commands', [])[:10]}
- Auth attempts: {len(session.get('auth_attempts', []))}

Retrieved threat intelligence:
{context}

Provide:
1. Attack classification
2. CVE mappings
3. MITRE ATT&CK techniques
4. Threat actor hypothesis
5. Recommended response

Cite all claims."""

        analysis = self.provider.generate(
            prompt=user_prompt,
            system=system_prompt,
            max_tokens=512,
            temperature=0.1
        )

        # Compute IQS: 0.4*cve_acc + 0.35*ttp_precision + 0.25*cite_rel
        has_citations = "[DOC" in analysis
        iqs = (0.4 * min(len(cves) / 3.0, 1.0) +
               0.35 * min(len(ttp_ids) / 4.0, 1.0) +
               0.25 * float(has_citations))

        return {
            "session_id": session.get("session_id"),
            "analysis": analysis,
            "cves": cves,
            "mitre_techniques": ttp_ids,
            "retrieved_docs": len(docs),
            "source_citations": [d["payload"].get("source") for d in docs],
            "iqs": round(iqs, 3),
            "chrollo_confidence": session.get("chrollo_confidence", 0),
        }
