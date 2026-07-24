"""
embeddings.py
Vector embedding & semantic distance analysis engine for AgentWall-Supply.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field

RISK_VECTOR_CLUSTERS = {
    "covert_exfiltration": [
        "exfiltrate", "secretly", "forward", "send", "upload", "token", "auth",
        "cookie", "session", "credential", "ssh", "rsa", "env", "key", "webhook",
        "http", "post", "remote", "server", "parameter", "payload", "stolen"
    ],
    "instruction_override": [
        "ignore", "disregard", "override", "bypass", "previous", "prior", "system",
        "prompt", "rules", "instructions", "do not follow", "forget", "instead"
    ],
    "anti_disclosure": [
        "do not tell", "dont tell", "never mention", "hide", "conceal", "user",
        "human", "silently", "without notification", "behind scenes", "covert"
    ],
    "priority_hijack": [
        "always call", "must invoke", "execute first", "prioritize", "before other",
        "do not use other", "ignore other tools", "primary tool"
    ]
}


def _char_ngrams(text: str, n: int = 3) -> list[str]:
    text = f"#{text.lower()}#"
    return [text[i:i+n] for i in range(len(text) - n + 1)]


def _word_ngrams(words: list[str], n: int = 2) -> list[str]:
    return ["_".join(words[i:i+n]) for i in range(len(words) - n + 1)]


def build_vector(text: str) -> dict[str, float]:
    clean_text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    clean_text = re.sub(r"[_\-]+", " ", clean_text).lower()
    words = re.findall(r"[a-z0-9]+", clean_text)
    
    term_counts: Counter[str] = Counter()
    for w in words:
        if len(w) > 1:
            term_counts[f"w:{w}"] += 1.0
            
    for bg in _word_ngrams(words, n=2):
        term_counts[f"bg:{bg}"] += 1.5
        
    for char_tg in _char_ngrams(clean_text, n=3):
        term_counts[f"cg:{char_tg}"] += 0.3
        
    if not term_counts:
        return {}
        
    norm = math.sqrt(sum(val * val for val in term_counts.values()))
    if norm == 0:
        return {}
        
    return {k: v / norm for k, v in term_counts.items()}


def cosine_similarity(vec1: dict[str, float], vec2: dict[str, float]) -> float:
    if not vec1 or not vec2:
        return 0.0
    common = set(vec1.keys()) & set(vec2.keys())
    return sum(vec1[k] * vec2[k] for k in common)


@dataclass
class EmbeddingAnalysis:
    similarity_to_name: float
    cluster_scores: dict[str, float] = field(default_factory=dict)
    covert_injection_risk: float = 0.0
    detected_paraphrases: list[str] = field(default_factory=list)

    @property
    def vector_penalty(self) -> int:
        score = 0
        if self.covert_injection_risk > 0.45:
            score += int(self.covert_injection_risk * 25)
        elif self.covert_injection_risk > 0.30 and self.detected_paraphrases:
            score += 10
        return min(score, 25)


def analyze_vector_embeddings(name: str, description: str) -> EmbeddingAnalysis:
    name_vec = build_vector(name)
    desc_vec = build_vector(description)
    sim_to_name = cosine_similarity(name_vec, desc_vec)
    
    cluster_scores = {}
    detected_paraphrases = []
    max_risk = 0.0
    
    for cluster_name, keywords in RISK_VECTOR_CLUSTERS.items():
        cluster_text = " ".join(keywords)
        cluster_vec = build_vector(cluster_text)
        vec_sim = cosine_similarity(desc_vec, cluster_vec)
        
        kw_hits = sum(1 for kw in keywords if any(k in description.lower() for k in kw.split()))
        hit_ratio = kw_hits / max(4, len(keywords))
        
        sim = round(max(vec_sim * 2.5, hit_ratio * 1.5), 3)
        sim = min(sim, 1.0)
        cluster_scores[cluster_name] = sim
        
        if sim >= 0.20:
            detected_paraphrases.append(f"Semantic match to {cluster_name} (sim: {sim:.2f})")
            if sim > max_risk:
                max_risk = sim
                
    return EmbeddingAnalysis(
        similarity_to_name=round(sim_to_name, 3),
        cluster_scores=cluster_scores,
        covert_injection_risk=round(max_risk, 3),
        detected_paraphrases=detected_paraphrases
    )
