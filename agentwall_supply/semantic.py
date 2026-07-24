"""
semantic.py
Static injection pattern detection & vector similarity engine for AgentWall-Supply.
"""

import re
import math
from collections import Counter
from dataclasses import dataclass, field

from .embeddings import analyze_vector_embeddings, EmbeddingAnalysis

_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("override_instructions", re.compile(
        r"\b(ignore|disregard|override)\b.{0,30}\b(previous|prior|system|above)\b.{0,20}\b(instructions?|prompt|rules?)\b",
        re.I), 9),
    ("anti_disclosure", re.compile(
        r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|mention|show|reveal)\b.{0,20}\b(user|human)\b", re.I), 9),
    ("secrecy_directive", re.compile(
        r"\b(secretly|silently|without (?:the )?user'?s? knowledge|behind the scenes)\b", re.I), 8),
    ("exfil_language", re.compile(
        r"\b(send|post|upload|forward|exfiltrat\w*)\b.{0,30}\b(token|credential|password|key|secret|api[_ ]?key|cookie|session)\b",
        re.I), 10),
    ("always_call_first", re.compile(
        r"\b(always|must)\b.{0,20}\b(call|invoke|run|use)\b.{0,20}\bthis\b.{0,20}\b(before|first|prior)\b", re.I), 7),
    ("deprioritize_other_tools", re.compile(
        r"\b(do not|don't|never)\b.{0,20}\b(use|call|trust)\b.{0,20}\bother\b.{0,10}\btools?\b", re.I), 8),
    ("embedded_url", re.compile(r"https?://[^\s\"'<>]+", re.I), 4),
    ("base64_blob", re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b"), 6),
    ("role_impersonation", re.compile(
        r"\b(you are now|act as|pretend to be)\b.{0,20}\b(system|admin|root|developer)\b", re.I), 7),
    ("data_scope_creep", re.compile(
        r"\b(read|access|scan)\b.{0,20}\b(all files|entire (?:disk|filesystem)|every file|home directory)\b", re.I), 7),
    ("sensitive_file_reference", re.compile(
        r"(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|\.env\b|\.pem\b|known_hosts|private key file|"
        r"credentials file|\.netrc)", re.I), 9),
    ("include_as_parameter", re.compile(
        r"\b(include|attach|pass|append)\b.{0,25}\b(contents?|output|result)\b.{0,20}\bas\b.{0,10}\bparam", re.I), 8),
]

_STOPWORDS = {
    "the", "a", "an", "to", "of", "and", "or", "in", "on", "for", "this",
    "that", "with", "is", "are", "be", "it", "as", "by", "from", "will",
    "can", "your", "you", "if", "then", "at",
}


def _tokenize(text: str) -> list[str]:
    words = re.findall(r"[a-zA-Z]+", text.lower())
    return [w for w in words if w not in _STOPWORDS and len(w) > 1]


def _split_identifier(name: str) -> list[str]:
    name = re.sub(r"[_\-]+", " ", name)
    name = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return _tokenize(name)


def _cosine_similarity(a: Counter, b: Counter) -> float:
    common = set(a) & set(b)
    dot = sum(a[t] * b[t] for t in common)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


@dataclass
class SemanticFinding:
    pattern_label: str
    severity: int
    matched_snippet: str


@dataclass
class SemanticResult:
    injection_findings: list[SemanticFinding] = field(default_factory=list)
    name_desc_similarity: float = 1.0
    embedding_analysis: EmbeddingAnalysis | None = None

    @property
    def injection_score(self) -> int:
        raw_score = sum(f.severity for f in self.injection_findings)
        if self.embedding_analysis:
            raw_score += self.embedding_analysis.vector_penalty
        return min(raw_score, 40)

    @property
    def mismatch_flag(self) -> bool:
        return self.name_desc_similarity < 0.12


def analyze_description(name: str, description: str) -> SemanticResult:
    findings = []
    for label, pattern, severity in _PATTERNS:
        m = pattern.search(description)
        if m:
            snippet = m.group(0)
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            findings.append(SemanticFinding(label, severity, snippet))

    name_tokens = Counter(_split_identifier(name))
    desc_tokens = Counter(_tokenize(description))
    similarity = 1.0
    if len(description) >= 15 and name_tokens:
        similarity = _cosine_similarity(name_tokens, desc_tokens)
        if similarity == 0.0 and desc_tokens:
            similarity = 0.0

    emb_analysis = analyze_vector_embeddings(name, description)
    if similarity > 0 and emb_analysis.similarity_to_name > 0:
        similarity = round((similarity + emb_analysis.similarity_to_name) / 2.0, 3)

    return SemanticResult(
        injection_findings=findings,
        name_desc_similarity=similarity,
        embedding_analysis=emb_analysis,
    )
