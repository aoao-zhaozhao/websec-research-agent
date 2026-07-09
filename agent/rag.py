"""
RAG 知识库模块 — 两阶段检索管线 (v0.5.1)。

管线:
  1. Stage 1 — Embedding 粗排: Qwen3-Embedding-0.6B → Chroma 向量检索 top_k × N
  2. Stage 2 — Reranker 精排: Qwen3-Reranker-0.6B CrossEncoder → 返回 top_k

模型均存储在项目内 agent/models/，不依赖外部下载。

依赖: chromadb, sentence-transformers, transformers, torch
"""

import os
import re
from pathlib import Path

from langchain_core.tools import tool


class RAGManager:
    """
    Chroma + Reranker 知识库管理器。

    用法:
        rag = RAGManager(AgentConfig())
        results = rag.search("SQL注入如何修复")       # 两阶段检索
        tool = rag.as_tool()                          # 转为 LangChain @tool
    """

    def __init__(self, config):
        self.config = config
        self.knowledge_dir = Path(config.knowledge_dir)
        self.persist_dir = str(Path(config.chroma_persist_dir))
        self.model_dir = str(Path(config.embedding_model_dir))
        self.reranker_dir = str(Path(config.reranker_model_dir))
        self.top_k = config.rag_top_k
        self.candidate_k = config.rag_top_k * config.rag_candidate_multiplier

        self._client = None
        self._collection = None
        self._embedding_fn = None
        self._reranker = None
        self._reranker_tokenizer = None
        self._reranker_model = None

    # ── Lazy properties ────────────────────────────

    @property
    def client(self):
        if self._client is None:
            import chromadb
            os.makedirs(self.persist_dir, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self.persist_dir)
        return self._client

    @property
    def embedding_fn(self):
        if self._embedding_fn is None:
            from chromadb.utils import embedding_functions
            if os.path.isdir(self.model_dir):
                self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name=self.model_dir
                )
            else:
                print(f"[RAG] 本地 Embedding 模型未找到 ({self.model_dir})，回退 HuggingFace")
                self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                    model_name="Qwen/Qwen3-Embedding-0.6B"
                )
        return self._embedding_fn

    @property
    def collection(self):
        if self._collection is None:
            name = "web_security_knowledge"
            try:
                self._collection = self.client.get_collection(
                    name=name,
                    embedding_function=self.embedding_fn,
                )
            except Exception:
                self._collection = self.client.create_collection(
                    name=name,
                    embedding_function=self.embedding_fn,
                    metadata={"description": "Web安全漏洞知识库"},
                )
                self._index_documents()
        return self._collection

    def _lazy_init_reranker(self):
        """懒初始化 Qwen3-Reranker（CrossEncoder / logit-based）。"""
        if self._reranker is not None:
            return

        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        if os.path.isdir(self.reranker_dir):
            path = self.reranker_dir
        else:
            print(f"[RAG] 本地 Reranker 模型未找到 ({self.reranker_dir})，回退 HuggingFace")
            path = "Qwen/Qwen3-Reranker-0.6B"

        self._reranker_tokenizer = AutoTokenizer.from_pretrained(
            path, padding_side="left"
        )
        self._reranker_model = AutoModelForCausalLM.from_pretrained(
            path,
            dtype=torch.float32,  # CPU inference
        ).eval()

        # —— yes/no token IDs ——
        self._token_false_id = self._reranker_tokenizer.convert_tokens_to_ids("no")
        self._token_true_id = self._reranker_tokenizer.convert_tokens_to_ids("yes")

        # —— prompt template ——
        self._reranker_prefix = (
            "<|im_start|>system\n"
            "Judge whether the Document meets the requirements based on the Query "
            'and the Instruct provided. Note that the answer can only be "yes" or "no".'
            "<|im_end|>\n<|im_start|>user\n"
        )
        self._reranker_suffix = (
            "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
        )
        self._prefix_tokens = self._reranker_tokenizer.encode(
            self._reranker_prefix, add_special_tokens=False
        )
        self._suffix_tokens = self._reranker_tokenizer.encode(
            self._reranker_suffix, add_special_tokens=False
        )

        self._reranker = True  # mark as initialized

    # ── Document indexing ──────────────────────────

    def _index_documents(self):
        md_files = sorted(self.knowledge_dir.glob("*.md"))
        if not md_files:
            print("[RAG] ⚠️ 知识库目录为空，跳过索引")
            return

        chunks_added = 0
        for md_file in md_files:
            chunks = self._chunk_markdown(md_file)
            if not chunks:
                continue

            ids = [f"{md_file.stem}:{i}" for i in range(len(chunks))]
            documents = [c["content"] for c in chunks]
            metadatas = [
                {"source": md_file.name, "title": c["title"], "char_count": len(c["content"])}
                for c in chunks
            ]

            self._collection.add(ids=ids, documents=documents, metadatas=metadatas)
            chunks_added += len(chunks)

        print(f"[RAG] ✅ 已索引 {len(md_files)} 个知识文件 → {chunks_added} 个向量块")

    @staticmethod
    def _chunk_markdown(filepath: Path) -> list[dict]:
        text = filepath.read_text(encoding="utf-8")
        sections = re.split(r"\n(?=## )", text)
        chunks = []

        for sec in sections:
            sec = sec.strip()
            if not sec:
                continue
            title_match = re.match(r"^#{1,3}\s+(.+)", sec)
            title = title_match.group(1).strip() if title_match else filepath.stem

            if len(sec) > 2000:
                paragraphs = sec.split("\n\n")
                buffer = ""
                for p in paragraphs:
                    if len(buffer) + len(p) > 2000 and buffer:
                        chunks.append({"title": title, "content": buffer.strip()})
                        buffer = p
                    else:
                        buffer = f"{buffer}\n\n{p}" if buffer else p
                if buffer.strip():
                    chunks.append({"title": title, "content": buffer.strip()})
            else:
                chunks.append({"title": title, "content": sec})

        return chunks

    # ── Search ─────────────────────────────────────

    def search(self, query: str) -> str:
        """
        两阶段检索: Embedding 粗排 → Reranker 精排。

        Args:
            query: 搜索关键词 / 问题描述
        Returns:
            格式化的检索结果（给 Agent 阅读）
        """
        # Stage 1: Chroma vector search → N candidates
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=self.candidate_k,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            return f"[search_knowledge] 检索出错: {str(e)}"

        if not results["documents"] or not results["documents"][0]:
            return "[search_knowledge] 未找到匹配的知识条目。"

        docs = results["documents"][0]
        metas = results["metadatas"][0]
        distances = results["distances"][0]

        # Stage 2: Reranker 精排
        if len(docs) > self.top_k:
            docs, metas, distances = self._rerank(query, docs, metas, distances)

        # Format results
        return self._format_results(query, docs, metas, distances)

    def _rerank(self, query: str, docs: list, metas: list, distances: list) -> tuple:
        """
        用 Qwen3-Reranker 对候选文档精排，返回 top_k。

        使用 yes/no logit 分数: P(yes) 越高越相关。
        """
        try:
            self._lazy_init_reranker()

            instruction = (
                "Given a web security vulnerability query, retrieve relevant "
                "knowledge entries that describe the vulnerability pattern, "
                "CVE details, CVSS score, or remediation code examples."
            )
            pairs = [
                f"<Instruct>: {instruction}\n<Query>: {query}\n<Document>: {doc}"
                for doc in docs
            ]

            # Tokenize with reranker prompt template
            import torch

            max_len = 8192
            inputs = self._reranker_tokenizer(
                pairs,
                padding=False,
                truncation="longest_first",
                return_attention_mask=False,
                max_length=max_len - len(self._prefix_tokens) - len(self._suffix_tokens),
            )
            for i, ele in enumerate(inputs["input_ids"]):
                inputs["input_ids"][i] = (
                    self._prefix_tokens + ele + self._suffix_tokens
                )
            inputs = self._reranker_tokenizer.pad(
                inputs, padding="max_length", return_tensors="pt", max_length=max_len
            )

            with torch.no_grad():
                batch_logits = self._reranker_model(**inputs).logits[:, -1, :]
                true_vec = batch_logits[:, self._token_true_id]
                false_vec = batch_logits[:, self._token_false_id]
                stacked = torch.stack([false_vec, true_vec], dim=1)
                scores = torch.nn.functional.log_softmax(stacked, dim=1)[:, 1].exp().tolist()

            # Sort by reranker score descending
            ranked = sorted(
                zip(scores, docs, metas, distances),
                key=lambda x: x[0],
                reverse=True,
            )

            top_scores, top_docs, top_metas, top_distances = [], [], [], []
            for s, d, m, dist in ranked[: self.top_k]:
                top_scores.append(s)
                top_docs.append(d)
                top_metas.append(m)
                top_distances.append(dist)

            return top_docs, top_metas, top_distances

        except Exception as e:
            # Reranker 失败时降级为 top_k 按原距离返回
            print(f"[RAG] ⚠️ Reranker 失败 ({e})，降级为距离排序")
            return (
                docs[: self.top_k],
                metas[: self.top_k],
                distances[: self.top_k],
            )

    def _format_results(self, query: str, docs: list, metas: list, distances: list) -> str:
        """格式化检索结果为 Agent 可读文本。"""
        lines = [
            f'[search_knowledge] 查询: "{query}" → 找到 {len(docs)} 条相关知识:\n'
        ]
        for i, (doc, meta, dist) in enumerate(zip(docs, metas, distances), 1):
            relevance = "★" if dist < 0.8 else "☆"
            lines.append(f"── 结果 #{i} {relevance} (距离: {dist:.3f}) ──")
            lines.append(f"来源: {meta.get('source', '?')}  |  章节: {meta.get('title', '?')}")
            lines.append("")
            lines.append(doc[:1500])
            lines.append("")
        return "\n".join(lines)

    # ── LangChain tool ─────────────────────────────

    def as_tool(self):
        rag = self

        @tool
        def search_knowledge(query: str) -> str:
            """
            在 Web 安全知识库中搜索已知漏洞模式、CVE 案例和修复方案。

            知识库包含:
                - OWASP Top 10 (2021) 漏洞分类和修复建议
                - 精选 CVE 案例库 (SQL注入 / XSS / SSRF / CSRF / RCE 等)
                - 各类型漏洞的代码级修复方案和最佳实践

            使用时机:
                当你通过扫描工具发现可疑行为时，用本工具搜索相关的已知漏洞模式、
                CVE 编号、CVSS 评分和修复建议，将结果融入到最终报告中。

            参数:
                query: 搜索查询，如 "SQL注入修复方案" 或 "CSP缺失修复" 或 "XSS CVE"
            """
            return rag.search(query)

        return search_knowledge


def create_search_knowledge_tool(config) -> tuple:
    """便捷工厂: 返回 (search_knowledge_tool, rag_manager)。"""
    rag = RAGManager(config)
    _ = rag.collection  # trigger indexing on first use
    return rag.as_tool(), rag
