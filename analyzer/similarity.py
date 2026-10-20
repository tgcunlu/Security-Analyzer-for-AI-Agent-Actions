"""Find InjecAgent attacks that are similar to an analyzed case (TF-IDF + cosine similarity)."""

import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

REQUEST_WEIGHT = 0.3
ACTION_WEIGHT = 0.7


def split_tool_name(name):
    """Turn a CamelCase tool name into words: "GmailSendEmail" -> "Gmail Send Email"."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)


def action_to_text(actions):
    """All steps of an action as one piece of text."""
    return " ".join(f"{split_tool_name(step.tool)} {step.input}" for step in actions)


class SimilaritySearch:
    def __init__(self, scenarios):
        self.scenarios = scenarios.reset_index(drop=True)
        request_texts = self.scenarios["user_instruction"].tolist()
        attack_texts = [
            " ".join(split_tool_name(tool) for tool in row.attacker_tools) + " " + row.attacker_instruction
            for row in self.scenarios.itertuples()
        ]
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.vectorizer.fit(request_texts + attack_texts)
        self.request_matrix = self.vectorizer.transform(request_texts)
        self.attack_matrix = self.vectorizer.transform(attack_texts)

    def search(self, user_request, actions, top_k=5, min_score=0.05):
        """Return up to top_k similar scenarios, one per distinct attack, best first."""
        request_vector = self.vectorizer.transform([user_request])
        action_vector = self.vectorizer.transform([action_to_text(actions)])
        request_scores = cosine_similarity(request_vector, self.request_matrix)[0]
        action_scores = cosine_similarity(action_vector, self.attack_matrix)[0]
        scores = REQUEST_WEIGHT * request_scores + ACTION_WEIGHT * action_scores

        results = []
        seen_attacks = set()
        for index in scores.argsort()[::-1]:
            score = float(scores[index])
            if score < min_score or len(results) == top_k:
                break
            row = self.scenarios.iloc[index]
            if row["attacker_instruction"] in seen_attacks:
                continue
            seen_attacks.add(row["attacker_instruction"])
            results.append({
                "scenario_id": row["scenario_id"],
                "score": round(score, 3),
                "attack_type": row["attack_type"],
                "attacker_tools": row["attacker_tools"],
                "attacker_instruction": row["attacker_instruction"],
            })
        return results
