"""naming.py —— 慢系统命名双车道（T2a 嵌入自命名 / T2b VLM 深理解）。

三层文本：短名 ≤16 字 + 细节描述（不设上限，监控事件需细节语言）+ rationale。
VLM 计数器外露——【省】验收线（重复场景调用趋零）的度量来源。
"""

SHORT_NAME_MAX = 16


class NamingLanes:
    """命名车道：模式库命中 → 自命名（零 VLM）；新异 → VLM 深理解 + 建档。"""

    def __init__(self, patterns, vlm=None):
        """patterns: PatternLibrary；vlm: callable(摘要, 帧) → {short_name, detail,
        rationale, conf}（None/undecidable 视为弃权）。vlm 计数器外露。"""
        self.patterns = patterns
        self.vlm = vlm
        self.vlm_calls = 0

    def on_segment(self, seg, *, emb=None, modality=None, keyframes=None,
                   context=None):
        """段关闭入口：返回 {short_name, detail, rationale, source, pattern, vlm_used}。

        T2a 命中已验证模式 → 自命名（零 VLM）；
        T2b draft/新异 → VLM 深理解（1 帧+环境档案上下文，细节不设上限）。
        """
        m = self.patterns.match_or_record(seg["signature"], emb, modality)
        p = m["pattern"]
        self.patterns.record_hit(p, seg.get("tod"), modality)

        if m["hit"] and p.get("name"):
            # T2a 自命名：命中已命名模式（含 draft）——零 VLM，一致性计数随命中累积
            self.patterns.record_name(p["id"], p["name"], p.get("detail"),
                                      consistent=True)
            return {"short_name": p["name"], "detail": p.get("detail") or "",
                    "rationale": "已知模式自命名", "source": "t2a-self",
                    "pattern": p, "vlm_used": False}

        # T2b VLM 深理解（新异/draft）
        out = None
        if self.vlm:
            self.vlm_calls += 1
            out = self.vlm(seg, keyframes or [])
        if out and out.get("short_name"):
            name = str(out["short_name"])[:SHORT_NAME_MAX]
            detail = str(out.get("detail") or "")
            self.patterns.record_name(p["id"], name, detail, consistent=True)
            return {"short_name": name, "detail": detail,
                    "rationale": str(out.get("rationale") or "")[:60],
                    "source": "t2b-vlm", "pattern": p, "vlm_used": True}
        # VLM 不可用/弃权：模板占位（诚实降级，事件流仍可读）
        return {"short_name": f"未命名事件 {seg.get('segment_id', '')}"[-16:],
                "detail": "", "rationale": "VLM 不可用，模板占位",
                "source": "fallback", "pattern": p, "vlm_used": False}

    def stats(self):
        return {"vlm_calls": self.vlm_calls}
