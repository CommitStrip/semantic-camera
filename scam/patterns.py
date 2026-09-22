"""patterns.py —— PatternLibrary 习惯化模式库（语义层学习主轴）。

信任分层：draft → model-verified（连续一致命名 ≥verify_n）
        → human-verified（管理员金标 ≥human_n 样本）。
审计抽检 5%（随机可注入）；双嵌入档案（§6.4 昼/夜分开）；降级保留计数。
联合匹配：同模态且双方有嵌入 → 0.7 结构 + 0.3 嵌入（v3.8 常态分量）。

持久化纪律（LC-046 S1）：
- `to_document()`/`snapshot()` 输出**固定版本化结构**
  （`schema`/`kind`/`version`/`seq`/`patterns`，模式记录字段集合固定）；
- `load_document()`/`restore()` 在**改变自身任何状态之前**完成全量校验：坏类型、
  未知/缺失字段、重复 id、不支持的状态、畸形嵌入记录（维度/样本数/非有限值）一律
  `PatternPersistenceError`；校验通过后序号推进到已恢复 `pat-N` 之后，新 id 不可能碰撞；
- `load_library()`/`save_library()`/`save_pattern()`/`delete_pattern()` 复用既有
  `patterns`/`pattern_embeddings` 两表（不新增 schema、不做迁移）；写入语句均为固定
  文本 + `?` 参数绑定，绝不拼接取值。这些写函数**不自行提交事务**，以便与调用方
  （慢系统单条结果事务）合并成一次提交；独立使用时由调用方 commit。

质心精度（唯一存储精度 = float32）：
- `attach_embedding()` 入档即把质心归一到 `float32_value()`，文档/行反序列化路径
  （`_embedding_record()`）同样归一。内存值、`snapshot()` 文本与
  `pattern_embeddings.centroid` 的 BLOB 三者同值，`save`→`load` 得到的规范快照
  逐字节稳定——**绝不假装 Python float64 中间值能存活于既有 float32 列格式**；
- 有限但超出 float32 表示范围的数值无法落库，如实拒绝（`PatternPersistenceError`）。
"""

import json
import re
import struct

EMBED_WEIGHT = 0.3

PATTERN_LIBRARY_SCHEMA = "scam.pattern-library/v1"
PATTERN_LIBRARY_KIND = "pattern_library"
PATTERN_LIBRARY_VERSION = 1
PATTERN_LIBRARY_FIELDS = ("schema", "kind", "version", "seq", "patterns")
PATTERN_STATES = ("draft", "model-verified", "human-verified")
SIGNATURE_REQUIRED_KEYS = ("cls", "count", "zones", "lines", "modality", "tod",
                           "dur")
SIGNATURE_OPTIONAL_KEYS = ("dwell",)
SIGNATURE_FIELDS = SIGNATURE_REQUIRED_KEYS + SIGNATURE_OPTIONAL_KEYS
SIGNATURE_DEFAULT_DWELL = "无"
PATTERN_RECORD_FIELDS = ("id", "signature", "name", "detail", "state", "count",
                         "version", "llm_agree", "human_samples",
                         "expected_window", "last_audit", "embs")
PATTERN_PAYLOAD_FIELDS = ("llm_agree", "human_samples", "expected_window",
                          "last_audit")
PATTERN_MODALITY_MAX = 64
PATTERN_EMBEDDING_DIM_MAX = 4096
PATTERN_WINDOW_ITEMS_MAX = 64
PATTERN_ID_MAX = 64
PATTERN_ID_PATTERN = re.compile(r"^pat-([0-9]+)$")


class PatternPersistenceError(ValueError):
    """模式库快照/数据库行不合法；调用方必须 fail-closed，不得吞掉。"""


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
             "state": "draft", "count": 0, "version": 1, "llm_agree": 0,
             "human_samples": 0, "expected_window": {"tod": [], "modality": []},
             "last_audit": None, "embs": {}}
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
        """V-JEPA 段嵌入入档：按模态加权质心；维度不一致重置（防 NaN 污染）。

        质心入档前一律归一到 float32 存储精度（`float32_value()`），使内存值、快照
        值与 `pattern_embeddings.centroid` 的 BLOB 三者同值；新条目先完整算好再整体
        替换，量化失败不留下半更新的旧条目。
        """
        p = self.patterns.get(pattern_id)
        if not p or not isinstance(vec, (list, tuple)) or not vec or not modality:
            return None
        embs = p.setdefault("embs", {})
        cur = embs.get(modality)
        if not cur or not isinstance(cur.get("c"), list) or \
                cur.get("n", 0) <= 0 or len(cur["c"]) != len(vec):
            entry = {"c": [float32_value(item) for item in vec], "n": 1,
                     "dim": len(vec)}
        else:
            n = cur["n"]
            entry = {"c": [float32_value((v * n + x) / (n + 1))
                           for v, x in zip(cur["c"], vec)],
                     "n": n + 1, "dim": len(vec)}
        embs[modality] = entry
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

    def to_document(self):
        """固定版本化结构（可 JSON 序列化；与 `load_document` 输入同形）。"""
        return {
            "schema": PATTERN_LIBRARY_SCHEMA,
            "kind": PATTERN_LIBRARY_KIND,
            "version": PATTERN_LIBRARY_VERSION,
            "seq": counter_value(self.seq, "pattern.seq"),
            "patterns": [_pattern_record(self.patterns[pattern_id],
                                         strict=False)
                         for pattern_id in ordered_pattern_ids(self.patterns)],
        }

    def load_document(self, document):
        """整体替换本库；全量校验通过之前不改变任何自身状态。"""
        parsed = parse_document_source(document)
        records = validated_records(parsed)
        next_seq = next_sequence(parsed["seq"], records)
        patterns = {}
        for record in records:
            patterns[record["id"]] = _pattern_from_record(record)
        self.patterns = patterns
        self.seq = next_seq
        return self

    def snapshot(self):
        """固定结构 JSON 文本（`load_document` 可直接读回）。"""
        return json.dumps(self.to_document(), ensure_ascii=False)

    def restore(self, data):
        """从 snapshot 文档恢复；坏文档抛 `PatternPersistenceError` 且不改自身。"""
        return self.load_document(data)


def ordered_pattern_ids(patterns):
    """确定性顺序：pat-N 按数值升序，其余排在其后按字符串。"""
    def key(pattern_id):
        match = PATTERN_ID_PATTERN.match(pattern_id)
        return (0, int(match.group(1)), "") if match else (1, 0, pattern_id)
    return sorted(patterns, key=key)


def parse_document_source(source):
    """JSON 文本/字节或已是对象；其它类型一律拒绝。"""
    if isinstance(source, (bytes, bytearray)):
        try:
            source = bytes(source).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PatternPersistenceError(
                f"snapshot: 不是合法 UTF-8（{exc}）") from None
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except ValueError as exc:
            raise PatternPersistenceError(
                f"snapshot: 不是合法 JSON（{exc}）") from None
    if not isinstance(source, dict):
        raise PatternPersistenceError("snapshot: 根必须是对象")
    return source


def validated_records(document):
    """校验根结构与每个模式记录，返回规范化记录列表（含重复 id 检查）。"""
    if set(document) != set(PATTERN_LIBRARY_FIELDS):
        unknown = sorted(set(document) - set(PATTERN_LIBRARY_FIELDS))
        missing = sorted(set(PATTERN_LIBRARY_FIELDS) - set(document))
        raise PatternPersistenceError(
            f"snapshot: 根字段集合不符（未知={unknown} 缺失={missing}）")
    if document["schema"] != PATTERN_LIBRARY_SCHEMA:
        raise PatternPersistenceError("snapshot: schema 不符")
    if document["kind"] != PATTERN_LIBRARY_KIND:
        raise PatternPersistenceError("snapshot: kind 不符")
    version = document["version"]
    if isinstance(version, bool) or not isinstance(version, int) \
            or version != PATTERN_LIBRARY_VERSION:
        raise PatternPersistenceError("snapshot: 结构版本不支持")
    patterns = document["patterns"]
    if not isinstance(patterns, list):
        raise PatternPersistenceError("snapshot: patterns 必须是数组")
    records = []
    seen = set()
    for item in patterns:
        record = _pattern_record(item, strict=True)
        if record["id"] in seen:
            raise PatternPersistenceError(
                f"snapshot: 重复 pattern id {record['id']!r}")
        seen.add(record["id"])
        records.append(record)
    return records


def next_sequence(seq, records):
    """序号推进到已恢复 pat-N 之后；新 id 不可能与既有 id 碰撞。"""
    candidate = counter_value(seq, "snapshot.seq")
    highest = 0
    for record in records:
        match = PATTERN_ID_PATTERN.match(record["id"])
        if match:
            highest = max(highest, int(match.group(1)))
    return max(candidate, highest + 1)


def pattern_record(source, *, strict=False):
    """把模式对象规范化为固定记录；strict=True 时要求精确字段集合。"""
    return _pattern_record(source, strict=strict)


def signature_text(signature):
    """`patterns.signature` 列的确定性文本。"""
    return json.dumps(signature, ensure_ascii=False, separators=(",", ":"))


def pattern_payload(record):
    """`patterns.payload` 列的固定载荷（列外字段）。"""
    return json.dumps({key: record[key] for key in PATTERN_PAYLOAD_FIELDS},
                      ensure_ascii=False, separators=(",", ":"))


def float32_value(number):
    """float32 存储精度下的确定性取值（`pattern_embeddings.centroid` 既有格式）。

    质心只在这一种精度上存在：内存库、`snapshot()` 文本与 BLOB 三者用同一数值，
    快照才可能逐字节稳定。超出 float32 表示范围的有限值无法落库，这里如实抛出。
    """
    return struct.unpack("<f", struct.pack("<f", float(number)))[0]


def centroid_bytes(vector):
    """float32 小端质心字节（`pattern_embeddings.centroid` 既有格式）。"""
    values = [float(item) for item in vector]
    return struct.pack(f"<{len(values)}f", *values)


def centroid_vector(blob, dim):
    """字节 → 浮点质心；长度与 dim 不符即拒绝。"""
    if isinstance(blob, (bytes, bytearray, memoryview)):
        raw = bytes(blob)
    else:
        raise PatternPersistenceError("centroid: 必须是字节")
    if isinstance(dim, bool) or not isinstance(dim, int) or dim <= 0:
        raise PatternPersistenceError("centroid: dim 必须是正整数")
    if len(raw) != 4 * dim:
        raise PatternPersistenceError("centroid: 字节长度与 dim 不符")
    return list(struct.unpack(f"<{dim}f", raw))


def save_pattern(conn, pattern):
    """写入/更新单个模式及其全部模态质心行；不提交事务。"""
    record = _pattern_record(pattern, strict=False)
    conn.execute(
        "INSERT INTO patterns (pattern_id, camera, signature, name, detail,"
        " state, count, version, payload) VALUES (?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(pattern_id) DO UPDATE SET"
        " camera=COALESCE(patterns.camera, excluded.camera),"
        " signature=excluded.signature, name=excluded.name,"
        " detail=excluded.detail, state=excluded.state, count=excluded.count,"
        " version=excluded.version, payload=excluded.payload",
        (record["id"], None, signature_text(record["signature"]),
         record["name"], record["detail"], record["state"], record["count"],
         record["version"], pattern_payload(record)))
    for modality in sorted(record["embs"]):
        embedding = record["embs"][modality]
        conn.execute(
            "INSERT INTO pattern_embeddings"
            " (pattern_id, modality, centroid, dim, n) VALUES (?,?,?,?,?)"
            " ON CONFLICT(pattern_id, modality) DO UPDATE SET"
            " centroid=excluded.centroid, dim=excluded.dim, n=excluded.n",
            (record["id"], modality, centroid_bytes(embedding["c"]),
             embedding["dim"], embedding["n"]))


def delete_pattern(conn, pattern_id):
    """删除模式及其全部质心行（先子表后主表，避免外键违例）；不提交事务。"""
    conn.execute(
        "DELETE FROM pattern_embeddings WHERE pattern_id=?", (pattern_id,))
    conn.execute("DELETE FROM patterns WHERE pattern_id=?", (pattern_id,))


def save_library(conn, library):
    """把整个库**整档镜像**进既有两表：写全部模式与质心，并删除库中已不存在的
    模式行（含被逐出的 draft）。

    这是"独占该库"的调用方接口：删除面覆盖整张 `patterns` 表。若同一数据库还有
    其它写入者（例如按相机分档的会话），请改用 `save_pattern()` 只写变更行，或让
    慢系统按 `run_once` 的单条事务路径持久化（它只写本次触及的模式与本次逐出的
    draft，绝不删除其它行）。
    """
    records = library.to_document()["patterns"]
    keep = set()
    for record in records:
        save_pattern(conn, record)
        keep.add(record["id"])
    existing = set()
    for row in conn.execute("SELECT pattern_id FROM patterns"):
        value = tuple(row)[0]
        if isinstance(value, str):
            existing.add(value)
    for pattern_id in sorted(existing - keep):
        delete_pattern(conn, pattern_id)


def load_library(conn, *, sim_threshold=0.82, verify_n=5, human_n=3,
                 audit_rate=0.05, random=None, max_patterns=500):
    """从既有 `patterns`/`pattern_embeddings` 恢复完整 PatternLibrary。

    行结构不合法（坏 JSON、不支持状态、坏质心、孤儿嵌入）一律
    `PatternPersistenceError`，绝不半信半疑地载入。
    """
    raw = {}
    order = []
    for row in conn.execute(
            "SELECT pattern_id, camera, signature, name, detail, state, count,"
            " version, payload FROM patterns"):
        values = tuple(row)
        pattern_id = values[0]
        if not isinstance(pattern_id, str) or not pattern_id:
            raise PatternPersistenceError(
                "patterns.pattern_id: 必须是非空字符串")
        name = f"patterns[{pattern_id}]"
        record = {
            "id": pattern_id,
            "signature": _json_object(values[2], f"{name}.signature"),
            "name": values[3],
            "detail": values[4],
            "state": values[5],
            "count": _sqlite_int(values[6], f"{name}.count"),
            "version": _sqlite_int(values[7], f"{name}.version"),
            "embs": {},
        }
        record.update(_payload_extras(values[8], name))
        raw[pattern_id] = record
        order.append(pattern_id)
    for row in conn.execute(
            "SELECT pattern_id, modality, centroid, dim, n"
            " FROM pattern_embeddings"):
        pattern_id, modality, centroid, dim, count = tuple(row)
        record = raw.get(pattern_id)
        if record is None:
            raise PatternPersistenceError(
                "pattern_embeddings: 引用未知模式，拒绝载入")
        if not isinstance(modality, str) or not modality:
            raise PatternPersistenceError(
                "pattern_embeddings.modality: 必须是非空字符串")
        dim_value = _sqlite_int(dim, "pattern_embeddings.dim")
        record["embs"][modality] = {
            "c": centroid_vector(centroid, dim_value),
            "n": _sqlite_int(count, "pattern_embeddings.n"),
            "dim": dim_value,
        }
    library = PatternLibrary(sim_threshold=sim_threshold, verify_n=verify_n,
                             human_n=human_n, audit_rate=audit_rate,
                             random=random, max_patterns=max_patterns)
    patterns = {}
    for pattern_id in order:
        record = _pattern_record(raw[pattern_id], strict=True)
        patterns[record["id"]] = _pattern_from_record(record)
    library.patterns = patterns
    library.seq = next_sequence(0, list(patterns.values()))
    return library


def _pattern_from_record(record):
    """规范化记录 → 内存模式对象（字段顺序固定，二者同形）。"""
    return {key: record[key] for key in PATTERN_RECORD_FIELDS}


def _pattern_record(source, *, strict):
    if not isinstance(source, dict):
        raise PatternPersistenceError("pattern: 必须是对象")
    keys = set(source)
    if strict and keys != set(PATTERN_RECORD_FIELDS):
        unknown = sorted(keys - set(PATTERN_RECORD_FIELDS))
        missing = sorted(set(PATTERN_RECORD_FIELDS) - keys)
        raise PatternPersistenceError(
            f"pattern: 字段集合不符（未知={unknown} 缺失={missing}）")
    pattern_id = source.get("id")
    if not isinstance(pattern_id, str) or not pattern_id.strip() \
            or len(pattern_id) > PATTERN_ID_MAX:
        raise PatternPersistenceError("pattern.id: 必须是非空短字符串")
    if "signature" not in keys:
        raise PatternPersistenceError("pattern.signature: 缺失")
    name = source.get("name")
    if name is not None and not isinstance(name, str):
        raise PatternPersistenceError("pattern.name: 必须是字符串或 null")
    detail = source.get("detail")
    if detail is not None and not isinstance(detail, str):
        raise PatternPersistenceError("pattern.detail: 必须是字符串或 null")
    state = source.get("state", "draft")
    if state not in PATTERN_STATES:
        raise PatternPersistenceError(
            f"pattern.state: 不支持的状态 {state!r}")
    return {
        "id": pattern_id,
        "signature": _signature_record(source.get("signature")),
        "name": name,
        "detail": detail,
        "state": state,
        "count": counter_value(source.get("count", 0), "pattern.count"),
        "version": counter_value(source.get("version", 1), "pattern.version"),
        "llm_agree": counter_value(source.get("llm_agree", 0),
                                   "pattern.llm_agree"),
        "human_samples": counter_value(source.get("human_samples", 0),
                                       "pattern.human_samples"),
        "expected_window": _window_record(source.get("expected_window")),
        "last_audit": _audit_record(source.get("last_audit")),
        "embs": _embeddings_record(source.get("embs")),
    }


def counter_value(value, name):
    """非负整数校验（bool 不算整数）。"""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PatternPersistenceError(f"{name}: 必须是非负整数")
    return value


def _signature_record(value):
    if not isinstance(value, dict):
        raise PatternPersistenceError("pattern.signature: 必须是对象")
    keys = set(value)
    if not set(SIGNATURE_REQUIRED_KEYS) <= keys \
            or not keys <= set(SIGNATURE_FIELDS):
        raise PatternPersistenceError("pattern.signature: 键集不符")
    for key in ("cls", "zones", "lines"):
        items = value[key]
        if not isinstance(items, (list, tuple)) or \
                not all(isinstance(item, str) for item in items):
            raise PatternPersistenceError(
                f"pattern.signature.{key}: 必须是字符串数组")
    for key in ("count", "modality", "tod", "dur"):
        if not isinstance(value[key], str):
            raise PatternPersistenceError(
                f"pattern.signature.{key}: 必须是字符串")
    dwell = value.get("dwell", SIGNATURE_DEFAULT_DWELL)
    if not isinstance(dwell, str):
        raise PatternPersistenceError("pattern.signature.dwell: 必须是字符串")
    return {"cls": list(value["cls"]), "count": value["count"],
            "zones": list(value["zones"]), "lines": list(value["lines"]),
            "modality": value["modality"], "tod": value["tod"],
            "dur": value["dur"], "dwell": dwell}


def _window_record(value):
    if value is None:
        return {"tod": [], "modality": []}
    if not isinstance(value, dict) or set(value) != {"tod", "modality"}:
        raise PatternPersistenceError("pattern.expected_window: 结构不符")
    window = {}
    for key in ("tod", "modality"):
        items = value[key]
        if not isinstance(items, (list, tuple)) \
                or len(items) > PATTERN_WINDOW_ITEMS_MAX:
            raise PatternPersistenceError(
                f"pattern.expected_window.{key}: 必须是有界数组")
        merged = []
        for item in items:
            if item is None:
                if None not in merged:
                    merged.append(None)
                continue
            if not isinstance(item, str) or not item:
                raise PatternPersistenceError(
                    f"pattern.expected_window.{key}: 元素必须是字符串或 null")
            if item not in merged:
                merged.append(item)
        window[key] = merged
    return window


def _audit_record(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"agree"}:
        raise PatternPersistenceError("pattern.last_audit: 结构不符")
    if not isinstance(value["agree"], bool):
        raise PatternPersistenceError("pattern.last_audit.agree: 必须是布尔")
    return {"agree": value["agree"]}


def _embeddings_record(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PatternPersistenceError("pattern.embs: 必须是对象")
    embs = {}
    for modality, embedding in value.items():
        if not isinstance(modality, str) or not modality \
                or len(modality) > PATTERN_MODALITY_MAX:
            raise PatternPersistenceError("pattern.embs: 模态名不合法")
        embs[modality] = _embedding_record(embedding, modality)
    return embs


def _embedding_record(value, modality):
    name = f"pattern.embs.{modality}"
    if not isinstance(value, dict):
        raise PatternPersistenceError(f"{name}: 必须是对象")
    keys = set(value)
    if not {"c", "n"} <= keys or not keys <= {"c", "n", "dim"}:
        raise PatternPersistenceError(f"{name}: 键集不符")
    vector = value["c"]
    if not isinstance(vector, (list, tuple)) or not vector \
            or len(vector) > PATTERN_EMBEDDING_DIM_MAX:
        raise PatternPersistenceError(f"{name}.c: 维度不合法")
    centroid = []
    for item in vector:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise PatternPersistenceError(f"{name}.c: 必须是数值")
        number = float(item)
        if number != number or number in (float("inf"), float("-inf")):
            raise PatternPersistenceError(f"{name}.c: 非有限数值")
        try:
            centroid.append(float32_value(number))
        except (OverflowError, struct.error):
            raise PatternPersistenceError(
                f"{name}.c: 超出 float32 存储范围") from None
    count = counter_value(value["n"], f"{name}.n")
    if count <= 0:
        raise PatternPersistenceError(f"{name}.n: 必须为正整数")
    dim = value.get("dim", len(centroid))
    if isinstance(dim, bool) or not isinstance(dim, int) \
            or dim != len(centroid):
        raise PatternPersistenceError(f"{name}.dim: 与质心维度不一致")
    return {"c": centroid, "n": count, "dim": dim}


def _json_object(value, name):
    if value is None:
        raise PatternPersistenceError(f"{name}: 缺失")
    if not isinstance(value, str):
        raise PatternPersistenceError(f"{name}: 必须是 JSON 文本")
    try:
        parsed = json.loads(value)
    except ValueError as exc:
        raise PatternPersistenceError(
            f"{name}: 不是合法 JSON（{exc}）") from None
    if not isinstance(parsed, dict):
        raise PatternPersistenceError(f"{name}: 必须是对象")
    return parsed


def _sqlite_int(value, name):
    if isinstance(value, bool):
        raise PatternPersistenceError(f"{name}: 必须是整数")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise PatternPersistenceError(f"{name}: 必须是整数")


def _payload_extras(payload, name):
    if payload is None:
        return {"llm_agree": 0, "human_samples": 0,
                "expected_window": {"tod": [], "modality": []},
                "last_audit": None}
    if not isinstance(payload, str):
        raise PatternPersistenceError(f"{name}.payload: 必须是文本")
    try:
        parsed = json.loads(payload)
    except ValueError as exc:
        raise PatternPersistenceError(
            f"{name}.payload: 不是合法 JSON（{exc}）") from None
    if not isinstance(parsed, dict) \
            or set(parsed) != set(PATTERN_PAYLOAD_FIELDS):
        raise PatternPersistenceError(f"{name}.payload: 字段集合不符")
    return dict(parsed)
