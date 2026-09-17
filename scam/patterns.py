"""patterns.py —— PatternLibrary 习惯化模式库（语义层学习主轴）。

信任分层：draft → model-verified（连续一致命名 ≥verify_n）
        → human-verified（管理员金标 ≥human_n 样本）。
审计抽检 5%（随机可注入）；双嵌入档案（§6.4 昼/夜分开）；降级保留计数。
联合匹配：同模态且双方有嵌入 → 0.7 结构 + 0.3 嵌入（v3.8 常态分量）。
"""

EMBED_WEIGHT = 0.3


def embedding_similarity(a, b):
    """真余弦（质心加权平均后范数<1 仍正确）；不可比或负值截 0。"""
    if not isinstance(a, (list, tuple)) or not isinstance(b, (list, tuple)):
        return None
    if len(a) != len(b) or not a:
        return None
    dot = na = nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0 or nb <= 0:
        return None
    c = dot / (na * nb) ** 0.5
    return max(0.0, min(1.0, c))


def segment_similarity(a, b):
    """签名结构分量加权 Jaccard（类别 .30/数量 .10/区域 .20/越线 .10/模态 .10/时段 .10/时长 .10/滞留 .10）。"""
    w = {"cls": 0.30, "count": 0.10, "zones": 0.20, "lines": 0.10,
         "modality": 0.10, "tod": 0.10, "dur": 0.10, "dwell": 0.00}

    def jac(x, y):
        A, B = set(x), set(y)
        if not A and not B:
            return 1.0
        inter = len(A & B)
        union = len(A | B)
        return inter / union if union else 0.0

    def eq(x, y):
        return 1.0 if x == y else 0.0

    return (w["cls"] * jac(a["cls"], b["cls"])
            + w["count"] * eq(a["count"], b["count"])
            + w["zones"] * jac(a["zones"], b["zones"])
            + w["lines"] * jac(a["lines"], b["lines"])
            + w["modality"] * eq(a["modality"], b["modality"])
            + w["tod"] * eq(a["tod"], b["tod"])
            + w["dur"] * eq(a["dur"], b["dur"])
            + w["dwell"] * eq(a.get("dwell", "无"), b.get("dwell", "无")))


def segment_similarity_joint(a, b, emb_a, emb_b):
    """结构 + 嵌入凸组合；缺任一嵌入时诚实退化纯结构。"""
    s = segment_similarity(a, b)
    e = embedding_similarity(emb_a, emb_b)
    if e is None:
        return s
    return (1 - EMBED_WEIGHT) * s + EMBED_WEIGHT * e


class PatternLibrary:
    def __init__(self, sim_threshold=0.82, verify_n=5, human_n=3,
                 audit_rate=0.05, random=None, max_patterns=500):
        self.sim_threshold = sim_threshold
        self.verify_n = verify_n
        self.human_n = human_n
        self.audit_rate = audit_rate
        self.random = random or __import__("random").random
        self.max_patterns = max_patterns
        self.patterns = {}
        self.seq = 1

    def match_or_record(self, signature, emb=None, modality=None):
        """联合相似度匹配（同模态嵌入参与）；未命中建 draft。返回 {pattern, sim, hit}。"""
        best, best_sim = None, 0.0
        for p in self.patterns.values():
            p_emb = (emb and modality and p["embs"].get(modality))
            p_vec = p_emb["c"] if p_emb else None
            sim = segment_similarity_joint(signature, p["signature"], emb, p_vec)
            if sim > best_sim:
                best_sim, best = sim, p
        if best is not None and best_sim >= self.sim_threshold:
            return {"pattern": best, "sim": best_sim, "hit": True}
        pid = f"pat-{self.seq}"
        self.seq += 1
        p = {"id": pid, "signature": signature, "name": None, "detail": None,
             "state": "draft", "count": 0, "llm_agree": 0, "human_samples": 0,
             "version": 1, "embs": {}}
        self.patterns[p["id"]] = p
        self._prune()
        return {"pattern": p, "sim": best_sim, "hit": False}

    def record_hit(self, pattern, tod, modality):
        """命中统计：预期窗口积累（时段/模态），计数递增。"""
        pattern["count"] = pattern.get("count", 0) + 1
        ew = pattern.setdefault("expected_window", {"tod": [], "modality": []})
        if tod not in ew["tod"]:
            ew["tod"].append(tod)
        if modality not in ew["modality"]:
            ew["modality"].append(modality)
        return pattern

    def record_name(self, pattern_id, short_name, detail, consistent):
        """命名回写：归档名字与细节。consistent=True 时一致性计数 +1，
        达 verify_n 自动晋升 model-verified（审计链驱动晋升的补充路径）。"""
        p = self.patterns.get(pattern_id)
        if not p:
            return None
        p["name"] = short_name or p.get("name")
        p["detail"] = detail or p.get("detail")
        if consistent:
            p["llm_agree"] = p.get("llm_agree", 0) + 1
            if p.get("state") == "draft" and p["llm_agree"] >= self.verify_n:
                p["state"] = "model-verified"
                p["version"] = p.get("version", 1) + 1
        else:
            p["llm_agree"] = 0
            p["state"] = "draft"
        return p

    def human_confirm(self, pattern_id, name=None, detail=None):
        """管理员金标：改名/补细节 + 样本计数 → human-verified。"""
        p = self.patterns.get(pattern_id)
        if not p:
            return None
        if name and name != p.get("name"):
            p["name"] = name
            p["version"] = p.get("version", 1) + 1
        if detail:
            p["detail"] = detail
        p["human_samples"] = p.get("human_samples", 0) + 1
        if p["human_samples"] >= self.human_n:
            p["state"] = "human-verified"
        return p

    def should_audit(self, pattern):
        return pattern.get("state") == "model-verified" and \
            self.random() < self.audit_rate

    def audit_result(self, pattern_id, agree):
        p = self.patterns.get(pattern_id)
        if not p:
            return None
        p["last_audit"] = {"agree": agree}
        if not agree:
            p["state"] = "draft"      # 降级保留 count
            p["version"] = p.get("version", 1) + 1
        return p

    def attach_embedding(self, pattern_id, vec, modality):
        """V-JEPA 段嵌入入档：按模态加权质心；维度不一致重置（防 NaN 污染）。"""
        p = self.patterns.get(pattern_id)
        if not p or not isinstance(vec, (list, tuple)) or not vec or not modality:
            return None
        embs = p.setdefault("embs", {})
        cur = embs.get(modality)
        if not cur or not isinstance(cur.get("c"), list) or \
                cur.get("n", 0) <= 0 or len(cur["c"]) != len(vec):
            embs[modality] = {"c": list(vec), "n": 1}
        else:
            n = cur["n"]
            merged = [(v * n + x) / (n + 1) for v, x in zip(cur["c"], vec)]
            embs[modality] = {"c": merged, "n": n + 1}
        return p

    def embedding_match(self, pattern, vec, modality):
        cur = (pattern.get("embs") or {}).get(modality)
        if not cur or not isinstance(cur.get("c"), list):
            return None
        return embedding_similarity(cur["c"], vec)

    def _prune(self):
        if len(self.patterns) <= self.max_patterns:
            return
        drafts = sorted((pid for pid, p in self.patterns.items()
                         if p.get("state") == "draft"),
                        key=lambda pid: self.patterns[pid].get("count", 0))
        for pid in drafts:
            del self.patterns[pid]
            if len(self.patterns) <= self.max_patterns:
                break

    def snapshot(self):
        import json
        return json.dumps(list(self.patterns.values()), ensure_ascii=False)

    def restore(self, data):
        import json
        for p in json.loads(data or "[]"):
            self.patterns[p["id"]] = p
