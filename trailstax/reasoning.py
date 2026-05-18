"""
TrailStax - reasoning.py
Contextual reasoning evaluation and comparison across AI models.
The 4th trust layer in the TrailStax stack.

Measures reasoning hops, dead ends, decision branches, and
confidence signals across Claude, GPT, Gemini, and Grok.
Signs and commits all results via TrailStax audit trail.
"""

import os
import uuid
import time
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from trail import TrailStax

# Available models
SUPPORTED_MODELS = ["claude", "gpt", "gemini", "grok"]

# Default context tags for auto-classification
CONTEXT_TAGS = [
    "security",
    "edtech",
    "legal",
    "code",
    "medical",
    "finance",
    "general"
]

REASONING_VERSION = "0.1.0"

@dataclass
class ReasoningStep:
    """A single hop in a model's reasoning chain."""
    step_id: str
    model: str
    content: str
    step_type: str  # "hop", "dead_end", "decision", "confidence"
    confidence: float  # 0.0 - 1.0
    sequence: int

@dataclass
class ModelResult:
    """Full reasoning result from a single model."""
    model: str
    response: str
    steps: list
    reasoning_hops: int
    dead_ends: int
    decision_branches: int
    confidence_avg: float
    latency_ms: float
    score: float = 0.0
    rank: int = 0

@dataclass
class ReasoningSession:
    """A complete multi-model reasoning evaluation session."""
    session_id: str
    prompt: str
    models: list
    auto_context: str
    user_context: Optional[str]
    timestamp: float
    results: list = field(default_factory=list)
    trail_hash: str = ""

def classify_context(prompt: str) -> str:
    """Auto-classify prompt into a context tag."""
    prompt_lower = prompt.lower()
   
    keywords = {
        "security": ["vulnerability", "threat", "attack", "firewall", "breach", "malware", "exploit", "audit"],
        "edtech": ["student", "teacher", "learning", "education", "curriculum", "school", "grade", "course"],
        "legal": ["contract", "law", "compliance", "regulation", "liability", "clause", "legal", "court"],
        "code": ["function", "code", "debug", "programming", "script", "error", "deploy", "repository"],
        "medical": ["patient", "diagnosis", "treatment", "symptom", "clinical", "health", "medical"],
        "finance": ["investment", "market", "trade", "portfolio", "risk", "revenue", "financial", "crypto"],
    }
   
    scores = {context: 0 for context in keywords}
   
    for context, words in keywords.items():
        for word in words:
            if word in prompt_lower:
                scores[context] += 1
   
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "general"

def dispatch(prompt: str, models: list) -> list:
    """Send prompt to selected models sequentially and collect results."""
    results = []

    for model in models:
        if model not in SUPPORTED_MODELS:
            print(f"[reasoning] Skipping unsupported model: {model}")
            continue

        print(f"[reasoning] Querying {model}...")
        start = time.time()

        try:
            response, steps = query_model(model, prompt)
            latency_ms = (time.time() - start) * 1000

            hops = len([s for s in steps if s.step_type == "hop"])
            dead_ends = len([s for s in steps if s.step_type == "dead_end"])
            branches = len([s for s in steps if s.step_type == "decision"])
            confidence_avg = (
                sum(s.confidence for s in steps) / len(steps) if steps else 0.0
            )

            result = ModelResult(
                model=model,
                response=response,
                steps=steps,
                reasoning_hops=hops,
                dead_ends=dead_ends,
                decision_branches=branches,
                confidence_avg=round(confidence_avg, 3),
                latency_ms=round(latency_ms, 2),
            )
            results.append(result)

        except Exception as e:
            print(f"[reasoning] Error querying {model}: {e}")

    return results

def query_model(model: str, prompt: str) -> tuple:
    """Query a single model and parse reasoning steps from response."""
    import anthropic
    import openai
    import google.generativeai as genai

    system_prompt = """You are a reasoning engine. Think through this step by step.
For each step in your reasoning:
- Start with STEP: for a reasoning hop
- Start with DEAD_END: if an approach doesn't work
- Start with DECISION: at a branching point
- Start with CONFIDENCE: [0.0-1.0] to express certainty
Be explicit about your reasoning process."""

    response_text = ""

    if model == "claude":
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": f"{system_prompt}\n\n{prompt}"}]
        )
        response_text = message.content[0].text

    elif model == "gpt":
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        completion = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content

    elif model == "gemini":
        genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
        gemini = genai.GenerativeModel("gemini-1.5-pro")
        result = gemini.generate_content(f"{system_prompt}\n\n{prompt}")
        response_text = result.text

    elif model == "grok":
        client = openai.OpenAI(
            api_key=os.environ.get("GROK_API_KEY"),
            base_url="https://api.x.ai/v1"
        )
        completion = client.chat.completions.create(
            model="grok-3",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        response_text = completion.choices[0].message.content

    steps = parse_steps(model, response_text)
    return response_text, steps

def parse_steps(model: str, response: str) -> list:
    """Parse reasoning steps from model response."""
    steps = []
    sequence = 0

    for line in response.split("\n"):
        line = line.strip()
        if not line:
            continue

        step_type = None
        confidence = 0.7  # default

        if line.startswith("STEP:"):
            step_type = "hop"
            content = line[5:].strip()
        elif line.startswith("DEAD_END:"):
            step_type = "dead_end"
            content = line[9:].strip()
        elif line.startswith("DECISION:"):
            step_type = "decision"
            content = line[9:].strip()
        elif line.startswith("CONFIDENCE:"):
            step_type = "confidence"
            content = line[11:].strip()
            try:
                confidence = float(content.split()[0])
                content = " ".join(content.split()[1:])
            except:
                confidence = 0.7
        else:
            continue

        step = ReasoningStep(
            step_id=str(uuid.uuid4())[:8],
            model=model,
            content=content,
            step_type=step_type,
            confidence=confidence,
            sequence=sequence
        )
        steps.append(step)
        sequence += 1

    return steps

def score_results(results: list) -> list:
    """Compute reasoning scores for each model result."""
    for result in results:
        hop_score        = min(result.reasoning_hops * 10, 40)
        dead_end_penalty = result.dead_ends * 5
        branch_score     = min(result.decision_branches * 8, 24)
        confidence_score = result.confidence_avg * 20
        speed_score      = max(0, 10 - (result.latency_ms / 1000))

        result.score = round(
            hop_score
            - dead_end_penalty
            + branch_score
            + confidence_score
            + speed_score,
            2
        )

    return results


def compare_results(results: list) -> list:
    """Rank models by score and attach comparative rank."""
    sorted_results = sorted(results, key=lambda r: r.score, reverse=True)
    for i, result in enumerate(sorted_results):
        result.rank = i + 1
    return sorted_results


def build_comparison_report(session: ReasoningSession) -> dict:
    """Build a structured comparison report for the session."""
    return {
        "session_id":    session.session_id,
        "prompt":        session.prompt,
        "auto_context":  session.auto_context,
        "user_context":  session.user_context,
        "timestamp":     session.timestamp,
        "models_evaluated": len(session.results),
        "rankings": [
            {
                "rank":               r.rank,
                "model":              r.model,
                "score":              r.score,
                "reasoning_hops":     r.reasoning_hops,
                "dead_ends":          r.dead_ends,
                "decision_branches":  r.decision_branches,
                "confidence_avg":     r.confidence_avg,
                "latency_ms":         r.latency_ms,
            }
            for r in session.results
        ],
        "winner": session.results[0].model if session.results else None,
        "trail_hash": session.trail_hash,
    }

def run_session(
    prompt: str,
    models: list = None,
    user_context: str = None,
    agent_id: str = "reasoning-agent-001",
    export: bool = True
) -> dict:
    """
    Run a full reasoning evaluation session.
   
    Args:
        prompt:       The prompt to evaluate across models
        models:       List of models to use (defaults to all four)
        user_context: Optional context override
        agent_id:     RealAgentID agent identifier
        export:       Whether to export trail to JSON
   
    Returns:
        Comparison report dict
    """
    if models is None:
        models = SUPPORTED_MODELS

    session_id   = str(uuid.uuid4())
    auto_context = classify_context(prompt)
    timestamp    = time.time()

    print(f"\n[reasoning] Session: {session_id[:8]}")
    print(f"[reasoning] Context: {auto_context}" +
          (f" -> overridden to: {user_context}" if user_context else ""))
    print(f"[reasoning] Models:  {models}\n")

    # Initialize TrailStax trail
    trail = TrailStax(agent_id=agent_id, session_id=session_id)
    trail.log("reasoning.session.start", {
        "prompt":       prompt[:100],
        "models":       models,
        "auto_context": auto_context,
        "user_context": user_context,
        "version":      REASONING_VERSION
    })

    # Dispatch to models
    results = dispatch(prompt, models)

    # Score and rank
    results = score_results(results)
    results = compare_results(results)

    # Log each result to trail
    for r in results:
        trail.log("reasoning.model.scored", {
            "model":              r.model,
            "score":              r.score,
            "rank":               r.rank,
            "reasoning_hops":     r.reasoning_hops,
            "dead_ends":          r.dead_ends,
            "decision_branches":  r.decision_branches,
            "confidence_avg":     r.confidence_avg,
            "latency_ms":         r.latency_ms,
        })

    # Build session
    session = ReasoningSession(
        session_id=session_id,
        prompt=prompt,
        models=models,
        auto_context=auto_context,
        user_context=user_context,
        timestamp=timestamp,
        results=results,
        trail_hash=trail._last_hash
    )

    # Log completion
    trail.log("reasoning.session.complete", {
        "winner":     results[0].model if results else None,
        "chain_valid": trail.verify_chain(),
        "trail_hash": trail._last_hash
    })

    # Export trail
    if export:
        filename = f"reasoning_{session_id[:8]}.json"
        trail.export(filename)
        print(f"\n[reasoning] Trail exported -> {filename}")

    report = build_comparison_report(session)
    print(f"\n[reasoning] Winner: {report['winner']} "
          f"(score: {results[0].score if results else 0})")

    return report

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python reasoning.py '<prompt>' [models] [context]")
        print("Example: python reasoning.py 'How do I secure a CI/CD pipeline?' claude gpt")
        sys.exit(1)

    prompt       = sys.argv[1]
    models       = sys.argv[2:] if len(sys.argv) > 2 else None
    user_context = None

    # If last arg is a context tag use it
    if models and models[-1] in CONTEXT_TAGS:
        user_context = models[-1]
        models       = models[:-1]

    if models == []:
        models = None

    report = run_session(
        prompt=prompt,
        models=models,
        user_context=user_context
    )

    print("\n--- COMPARISON REPORT ---")
    print(json.dumps(report, indent=2))


