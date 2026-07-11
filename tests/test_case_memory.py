from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agent.case_manager import CaseManager
from agent.evolution.store import EvolutionStore
from agent.rag import RAGManager
from agent.skill_manager import SkillManager


class CaseMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_case_manager_writes_structured_rag_document(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        record = manager.create(
            title="Trailing newline validation bypass",
            target="authorized CTF",
            summary="A validation bypass was confirmed.",
            evidence="The source exposed an unquoted shell command.",
            solution="Use a harmless proof before any further CTF step.",
            category="general",
            tags=["php", "ctf"],
        )

        document = Path(str(record["path"])).read_text(encoding="utf-8")
        self.assertIn("category: general", document)
        self.assertIn("## Evidence", document)
        self.assertIn("## Resolution", document)

    def test_rag_discovers_nested_case_documents(self):
        knowledge = self.root / "knowledge"
        case_path = knowledge / "cases" / "example.md"
        case_path.parent.mkdir(parents=True)
        case_path.write_text("# Case\n\n## Summary\n\nExample", encoding="utf-8")
        config = SimpleNamespace(
            knowledge_dir=str(knowledge),
            chroma_persist_dir=str(self.root / "chroma"),
            embedding_model_dir=str(self.root / "embedding"),
            reranker_model_dir=str(self.root / "reranker"),
            rag_top_k=4,
            rag_candidate_multiplier=3,
        )

        rag = RAGManager(config)
        self.assertEqual(rag._source_name(case_path), "cases/example.md")
        self.assertEqual(rag._knowledge_files(), [case_path])

    def test_case_similarity_requires_matching_category_and_tags(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        for title in ("First PHP case", "Second PHP case"):
            manager.create(
                title=title,
                target="authorized CTF",
                summary="summary",
                evidence="evidence",
                solution="solution",
                category="general",
                tags=["php", "command-injection"],
            )

        self.assertEqual(manager.count_similar("general", ["php"]), 2)
        self.assertEqual(manager.count_similar("auth", ["php"]), 0)

    def test_archive_handles_missing_agent_skill_document(self):
        store = EvolutionStore(self.root / "evolution.db")
        manager = SkillManager(self.root / "skills", store=store)
        manager.create("temporary-skill", "test", "body", "general")
        skill_path = self.root / "skills" / "general" / "temporary-skill"
        for child in skill_path.iterdir():
            child.unlink()
        skill_path.rmdir()

        self.assertTrue(manager.archive("temporary-skill"))
        self.assertEqual(store.get_skill("temporary-skill")["state"], "archived")
        store.close()


if __name__ == "__main__":
    unittest.main()
