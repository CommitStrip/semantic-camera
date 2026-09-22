"""scam.slow_core —— S1 慢系统持久化处理核心（LC-046，DEC-010）。

唯一输入=已闭合 review_segments（三层真值之一，本模块只读）；
输出=派生资产（segments 档案 / patterns / pattern_embeddings），永不创建、
取消或改写管理员告警真值；快路径零依赖零等待（本模块不进任何告警链）。

持久化与幂等：
- segments.segment_id = review_id，存在即已处理（天然水位）；同段只一份慢结果；
- patterns 表 payload 存 PatternLibrary 完整 dict（无损还原），列值为可查询
  投影；pattern_embeddings 同步存各模态质心 BLOB；
- 失败有界重试：meta 键 slow:retry:<rid> 计数，超 max_retries 写 failed 终态
  档并停止重试（队列不积压）。
"""

import copy
import json
import math
import os
import struct
import time
import uuid
from datetime import datetime

from .naming import SHORT_NAME_MAX
from .patterns import PATTERN_EMBEDDING_DIM_MAX, PatternLibrary
from .segments import build_signature, dur_bucket, tod_bucket

MAX_FRAMES = 3          # SC-B：provider 每段最多三帧（旧 linux_slow_path 合同）

MODALITY_DAY = "DAY-COLOR"
MODALITY_NIGHT = "NIGHT-BW"


class SlowPersistenceConflict(RuntimeError):
    """终态持久化时认领快照过期/被接管（CAS rowcount=0）。

    竞争失败的固定结构异常：不写任何终态、不计重试、留给下一轮观察。
    """


class SlowPersistenceBusy(RuntimeError):
    """连接存在调用方未提交事务：fail-closed，拒绝静默提交外部事务。"""


class SlowGenerationConflict(SlowPersistenceConflict):
    """库代数 CAS 冲突：内存快照已过期，拒绝覆盖（客户端重载后重试）。

    继承 SlowPersistenceConflict —— 既有冲突捕获点自动覆盖；独立类型便于
    调用方区分并触发显式重新加载。
    """



def _approx_modality(ts):
    """成像模态近似（S1 无 ICR 通道）：6-18 点按彩色、其余按夜视。"""
    return MODALITY_DAY if 6 <= datetime.fromtimestamp(ts).hour < 18 \
        else MODALITY_NIGHT


def _f32_blob(vec):
    return struct.pack("<%df" % len(vec), *vec)


def _f32_vec(blob):
    n = len(blob) // 4
    return list(struct.unpack("<%df" % n, bytes(blob))) if n else None


class SlowCore:
    """闭合审查段 → 签名 → 模式匹配/建档/命名 → 派生档案落库。

    provider 可选：缺席时新异段标 pending_naming（零 VLM 调用，诚实降级）；
    注入时仅对新异段调用一次 understand（vlm_calls 统计随返回上报）。
    """

    def __init__(self, conn, *, camera, sim_threshold=0.82,
                 max_retries=3, max_patterns=500, frame_loader=None):
        self.conn = conn
        self.camera = camera
        self.max_retries = max_retries
        # 认领所有者令牌：跨实例 CAS 的"谁"（同实例重试即时，异实例需陈旧）
        self.instance_id = uuid.uuid4().hex[:12]
        self._library = None
        # P0-B：内存库绑定加载时的库代数快照——写入路径的 generation CAS 依据
        self._library_generation_seen = None
        # SC-B：三帧证据注入点——loader(安全引用列表, 段上下文) → 帧列表；
        # None=内建安全解码。安全过滤（evidence_assets 索引+围栏）在调用
        # loader 之前完成，不安全引用绝不进入 loader。
        self.frame_loader = frame_loader
        self._library_args = dict(sim_threshold=sim_threshold,
                                  max_patterns=max_patterns)

    # ---------- 模式库持久化（跨重启复用） ----------

    def _row_id(self, pid):
        """持久化主键加相机命名空间：不同相机的 pat-1 绝不互撞
        （单库全局主键下，裸 pat-N 会让 ON CONFLICT 把 A 相机的行
        覆盖成 B 相机的 payload——数据污染）。内存 id 保持 pat-N。"""
        import re as _re
        safe = _re.sub(r"[^A-Za-z0-9_-]+", "-", self.camera).strip("-_") \
            or "cam"
        return f"pat-{safe}-{pid}"

    @staticmethod
    def _validate_stale_after(value):
        """P1-B：显式陈旧阈值校验（bool/非数值/NaN/±Inf/≤0 拒绝）。"""
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("stale_after_s 必须为有限正数（拒绝 bool/非数值）")
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            raise ValueError("stale_after_s 必须为有限正数（拒绝 NaN/±Inf/≤0）")
        return number

    def _failed_final_count(self):
        row = self.conn.execute(
            "SELECT COUNT(*) FROM segments WHERE camera=?"
            " AND json_extract(payload,'$.status')='failed'",
            (self.camera,)).fetchone()
        return int(row[0])

    def _read_generation_sql(self):
        """当前库代数（不 BEGIN、不 commit；由调用方保证快照语义）。"""
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='slow:lib:gen'").fetchone()
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):
            return 0

    def load_library(self):
        """patterns 表 → 内存 PatternLibrary（payload 无损还原）。

        P0-B：patterns 与 `slow:lib:gen` 必须在**同一读快照**内读取——
        连接不在事务时用短只读事务（BEGIN→读→rollback，不写不提交）；
        已在 SlowCore 自己的事务内则直接读当前快照。绝不 commit/rollback
        调用方外部事务。加载成功后更新 `_library_generation_seen`。
        """
        conn = self.conn
        own_snapshot = False
        if not conn.in_transaction:
            conn.execute("BEGIN")          # 只读快照，防 patterns/gen 错绑
            own_snapshot = True
        try:
            lib = PatternLibrary(**self._library_args)
            rows = conn.execute(
                "SELECT payload FROM patterns"
                " WHERE camera=? OR camera IS NULL",
                (self.camera,)).fetchall()
            restored = 0
            for row in rows:
                try:
                    p = json.loads(row[0])
                except (TypeError, ValueError):
                    continue
                if isinstance(p, dict) and p.get("id"):
                    lib.patterns[p["id"]] = p
                    restored += 1
            generation = self._read_generation_sql()
        finally:
            if own_snapshot:
                conn.rollback()            # 只读：结束快照，无写入
        if lib.patterns:
            seqs = []
            for pid in lib.patterns:
                text = str(pid)
                if text.startswith("pat-") and \
                        text.rsplit("-", 1)[-1].isdigit():
                    seqs.append(int(text.rsplit("-", 1)[-1]))
            lib.seq = max(seqs, default=0) + 1
        self._library = lib
        self._library_generation_seen = generation
        return restored

    @property
    def library(self):
        if self._library is None:
            self.load_library()
        return self._library

    def _require_clean_connection(self, operation):
        """P0-A 统一守卫：调用方存在未提交事务时 fail-closed。

        合同是 fail-closed（拒绝），不是嵌套接管——不得先 commit 外层、
        不得用 SAVEPOINT 吸收。所有公开写入/认领/金标入口在**任何查询与
        写入之前**调用本方法。
        """
        if self.conn.in_transaction:
            raise SlowPersistenceBusy(
                f"{operation}：连接存在调用方未提交事务，拒绝静默提交"
                "（fail-closed；请先 commit/rollback 后再调用）")

    # ---------- 输入聚合（三层真值只读） ----------

    def signature_for(self, review):
        """闭合审查段 → 八分量签名（全部来自数据库真值的确定性聚合）。"""
        t0, t1 = float(review["t_start"]), float(review["t_end"])
        objects = self.conn.execute(
            "SELECT cls,t_start,t_last,zones FROM tracked_objects"
            " WHERE camera=? AND t_last>=? AND t_start<=?",
            (self.camera, t0, t1)).fetchall()
        events = self.conn.execute(
            "SELECT cls,zone_id FROM semantic_events"
            " WHERE camera=? AND t_start<=? AND (t_end IS NULL OR t_end>=?)",
            (self.camera, t1, t0)).fetchall()

        classes = {o["cls"] for o in objects if o["cls"]}
        classes |= {e["cls"] for e in events if e["cls"]}
        zones = {e["zone_id"] for e in events if e["zone_id"]}
        for o in objects:
            try:
                zones |= {z for z in json.loads(o["zones"] or "[]") if z}
            except (TypeError, ValueError):
                pass

        # 峰值同时在场对象数：对象活跃区间的端点扫描
        points = []
        for o in objects:
            points.append((max(float(o["t_start"]), t0), 1))
            points.append((min(float(o["t_last"]), t1), -1))
        points.sort()
        peak = running = 0
        for _, delta in points:
            running += delta
            peak = max(peak, running)

        return build_signature(
            classes=classes, peak_count=peak, zones=zones, lines=[],
            modality=_approx_modality(t0), tod=tod_bucket(
                datetime.fromtimestamp(t0)),
            dur_ms=(t1 - t0) * 1000.0)

    # ---------- 段证据帧（V-JEPA 嵌入 / provider 三帧输入） ----------

    def _safe_evidence_refs(self, review, limit=MAX_FRAMES):
        """段内证据资产的**安全引用**列表（最多 limit 条）。

        P1-C(R1) 索引围栏：只接受 `kind='clean_best_frame'` +
        `state='available'` + `mime='image/jpeg'`——missing/corrupt/pending
        或错误 MIME 资产不进入 loader。路径仍须为证据根内相对路径：
        绝对路径、`..` 穿越、越栏一律丢弃；并做**规范化真实路径**复核，
        根内符号链接/目录联接指向根外时同样拒绝。本批对证据索引只读。
        """
        rows = self.conn.execute(
            "SELECT a.path FROM evidence_assets a"
            " JOIN tracked_objects o"
            "   ON a.owner_type='tracked_object'"
            "  AND a.owner_id=o.object_id"
            " WHERE o.camera=? AND o.t_last>=? AND o.t_start<=?"
            "   AND a.kind='clean_best_frame'"
            "   AND a.state='available'"
            "   AND a.mime='image/jpeg'"
            " ORDER BY o.t_last DESC LIMIT ?",
            (self.camera, float(review["t_start"]),
             float(review["t_end"]), int(limit))).fetchall()
        root = self._evidence_root()
        if root is None:
            return []
        norm_root = os.path.normcase(root)
        real_root = os.path.normcase(os.path.realpath(root))
        refs = []
        for row in rows:
            raw = row[0]
            if not raw or os.path.isabs(str(raw)):
                continue                     # 绝对路径：拒绝
            text = str(raw).replace("\\", "/")
            if ".." in text.split("/"):
                continue                     # 父目录穿越：拒绝
            candidate = os.path.abspath(os.path.join(root, text))
            normed = os.path.normcase(candidate)
            if normed != norm_root and \
                    not normed.startswith(norm_root + os.sep):
                continue                     # 越栏：拒绝
            # 规范化真实路径复核：根内符号链接指根外 → 拒绝
            real = os.path.normcase(os.path.realpath(candidate))
            if real != real_root and \
                    not real.startswith(real_root + os.sep):
                continue
            refs.append(text)
        return refs

    def _load_frames(self, review, limit=MAX_FRAMES):
        """加载段证据帧：返回 (frames, error_token|None)。

        安全过滤在 loader 之前完成（loader 只收安全引用）；loader 缺席=
        内建安全解码（不联网、不读索引外文件）；帧数硬上限三。

        P0-B(R1) 统一异常边界：调用 loader / 取迭代器 / 逐项迭代 / 截断
        全部在同一个 try 内——延迟异常（生成器迭代中抛出）同样固定降级；
        已部分取得的帧在异常时**丢弃**（不隐瞒 loader 失败）；loader 故障
        不使段进入 retry。仅证据加载异常在此降级——数据库/事务/generation
        CAS/终态持久化异常一律向上传播。
        """
        refs = self._safe_evidence_refs(review, limit)
        if not refs:
            return [], None                  # 无证据：诚实降级，非错误
        context = {"camera": self.camera,
                   "review_id": review.get("review_id"),
                   "t_start": review.get("t_start"),
                   "t_end": review.get("t_end")}
        if self.frame_loader is not None:
            frames = []
            try:
                loaded = self.frame_loader(refs, context)
                if loaded is None:
                    return [], None
                if isinstance(loaded, (str, bytes, bytearray)):
                    return [], "frames:invalid_output"
                for frame in loaded:          # 非可迭代→TypeError（同一边界）
                    if frame is not None:
                        frames.append(frame)
                    if len(frames) >= limit:
                        break
            except Exception as exc:
                return [], f"frames:{type(exc).__name__}"   # 部分帧丢弃
            return frames, None
        # 内建解码（同样只读安全引用）
        root = self._evidence_root()
        frames = []
        for ref in refs:
            try:
                import cv2
                frame = cv2.imread(os.path.join(root, ref),
                                   cv2.IMREAD_COLOR)
            except Exception:
                frame = None
            if frame is not None:
                frames.append(frame)
            if len(frames) >= limit:
                break
        return frames, None

    def frame_for(self, review):
        """取段代表帧（最新对象的 clean_best_frame 证据）→ BGR 或 None。

        三帧加载器的单帧封装；围栏与降级纪律同 `_load_frames`。
        """
        frames, _ = self._load_frames(review, limit=1)
        return frames[0] if frames else None

    def _evidence_root(self):
        """证据根 = 数据库同目录下的 evidence/（与 WorkbenchState 约定一致）。"""
        row = self.conn.execute(
            "PRAGMA database_list").fetchone()
        db_file = row[2] if row else ""
        if not db_file:
            return None
        return os.path.join(os.path.dirname(os.path.abspath(db_file)),
                            "evidence")

    def embedding_input(self, review):
        """worker 的 emb_fn 数据源：返回 (frame_bgr, modality) 或 (None, None)。"""
        frame = self.frame_for(review)
        if frame is None:
            return None, None
        return frame, _approx_modality(float(review["t_start"]))

    # ---------- 处理循环（认领 CAS：segments 占位行=互斥锁） ----------

    STALE_CLAIM_S = 600.0   # 异实例接管的陈旧阈值（同实例重试不受限）

    def _claim_is_provably_stale(self, owner, t_claim, stale_s, now=None):
        """fail-closed 陈旧证明：无法可靠证明"已超阈值"一律返回 False。

        拒绝：owner/t_claim 缺失或 null、bool、非数值、NaN/±Inf、无法换算。
        "无法证明陈旧"≠"按陈旧处理"——绝不据此改写活跃认领。
        """
        if owner is None or t_claim is None:
            return False
        if isinstance(t_claim, bool) or not isinstance(t_claim, (int, float)):
            return False
        value = float(t_claim)
        if not math.isfinite(value):
            return False
        moment = time.time() if now is None else now
        return (moment - value / 1e6) >= stale_s

    def _finalize_exhausted_claim(self, review_id, *, expected_owner,
                                  expected_t_claim):
        """耗尽认领专用收官（P0-B）：单事务、单 CAS、零慢系统依赖。

        只把"已无法再执行且已证明陈旧"的 claiming 行写成固定失败终态；
        不写 patterns/pattern_embeddings、不改 semantic_events、不调
        provider/embedder/frame_loader、不加 retry、不递增库代数。
        返回 True=收官成功；False=竞输（rollback，不覆盖赢家）。
        """
        conn = self.conn
        self._require_clean_connection("_finalize_exhausted_claim")
        payload = json.dumps({"status": "failed", "error": "retries_exhausted",
                              "final": True}, ensure_ascii=False,
                             separators=(",", ":"))
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE segments SET payload=? WHERE segment_id=?"
                " AND json_extract(payload,'$.status')='claiming'"
                " AND json_extract(payload,'$.owner')=?"
                " AND json_extract(payload,'$.t_claim')=?",
                (payload, review_id, expected_owner, expected_t_claim))
            if cur.rowcount != 1:
                conn.rollback()
                return False
            conn.commit()
            return True
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

    def pending_reviews(self, limit=20, *, recover_stale=False,
                        stale_after_s=None):
        """认领待办闭合审查段（计划快照 CAS + 耗尽收官决策表，SC-B-R2）。

        互斥语义：无行→INSERT 占位成功者独占；claiming 行按下表处理：

        | 情形 | 动作 |
        |---|---|
        | 异实例·未耗尽·`recover_stale=False` | 跳过 |
        | 异实例·未耗尽·过阈值·`True` | 计划快照 CAS 接管（刷新快照）后处理 |
        | 异实例·已耗尽·`False` | 跳过 |
        | 异实例·已耗尽·未过阈值 | 跳过（保持 claiming，本轮 failed=0） |
        | 异实例·已耗尽·过阈值·`True` | **不接管刷新**——按计划快照直接 CAS 收官
        | （`failed/retries_exhausted/final=true`），本轮 failed+1、backlog-1 |
        | 同实例·未耗尽 | 续跑（快照=当前行值） |
        | 同实例·已耗尽·未过阈值 | 跳过（活跃最后尝试保护） |
        | 同实例·已耗尽·过阈值 | 按当前计划快照 CAS 收官 |
        | 时间无法证明陈旧 | 一律跳过（fail-closed：不接管、不终态） |

        接管/收官 CAS 竞输均不处理、不重试、不写终态。返回条目携带
        claim_owner/claim_t_claim 快照，供持久化阶段终态 CAS 使用。
        """
        self._require_clean_connection("pending_reviews")   # P0-A：认领前守卫
        checked_stale = self._validate_stale_after(stale_after_s)
        stale_s = (self.STALE_CLAIM_S if checked_stale is None
                   else checked_stale)
        rows = self.conn.execute(
            "SELECT r.review_id, r.camera, r.t_start, r.t_end,"
            " json_extract(s.payload,'$.status') AS s_status,"
            " json_extract(s.payload,'$.owner') AS s_owner,"
            " json_extract(s.payload,'$.t_claim') AS s_tclaim"
            " FROM review_segments r"
            " LEFT JOIN segments s ON s.segment_id = r.review_id"
            " WHERE r.t_end IS NOT NULL AND r.camera=?"
            " AND (s.segment_id IS NULL OR s_status='claiming')"
            " ORDER BY r.t_start LIMIT ?",
            (self.camera, int(limit))).fetchall()
        claimed = []
        now_us = int(time.time() * 1e6)
        for row in rows:
            rid = row["review_id"]
            entry = dict(review_id=rid, camera=row["camera"],
                         t_start=row["t_start"], t_end=row["t_end"])
            if row["s_status"] == "claiming":
                old_owner = row["s_owner"]
                old_t = row["s_tclaim"]
                provably_stale = self._claim_is_provably_stale(
                    old_owner, old_t, stale_s)
                exhausted = self._retries(rid) >= self.max_retries
                same_instance = old_owner == self.instance_id
                if exhausted:
                    # 耗尽收官决策：仅"已证明陈旧 + （同实例 或 recover_stale）"
                    # 才按计划快照直接收官——绝不刷新 t_claim 后重新等待
                    can_finalize = provably_stale and                         (same_instance or recover_stale)
                    if can_finalize:
                        self._finalize_exhausted_claim(
                            rid, expected_owner=old_owner,
                            expected_t_claim=old_t)   # False=竞输，静默
                    continue        # 已耗尽：无论收官成败都不进本轮执行
                if same_instance:
                    entry["claim_owner"] = old_owner
                    entry["claim_t_claim"] = old_t
                    claimed.append(entry)
                    continue
                if not recover_stale or not provably_stale:
                    continue        # 不可接管（未开启/未过阈值/无法证明）
                # 陈旧接管：UPDATE 严格绑定计划快照（owner+t_claim）
                new_us = int(time.time() * 1e6)
                cur = self.conn.execute(
                    "UPDATE segments SET payload=? WHERE segment_id=?"
                    " AND json_extract(payload,'$.status')='claiming'"
                    " AND json_extract(payload,'$.owner')=?"
                    " AND json_extract(payload,'$.t_claim')=?",
                    (self._claim_payload(new_us), rid, old_owner, old_t))
                self.conn.commit()
                if cur.rowcount != 1:
                    continue        # 竞输/快照过期：留给下一轮观察
                entry["claim_owner"] = self.instance_id
                entry["claim_t_claim"] = new_us
                claimed.append(entry)
                continue
            # 无行：INSERT 占位即认领（rowcount=1 者独占）
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO segments"
                " (segment_id,camera,t_start,t_end,signature,detail,payload)"
                " VALUES (?,?,?,?,?,?,?)",
                (rid, row["camera"], row["t_start"], row["t_end"],
                 None, None, self._claim_payload(now_us)))
            self.conn.commit()
            if cur.rowcount == 1:
                entry["claim_owner"] = self.instance_id
                entry["claim_t_claim"] = now_us
                claimed.append(entry)
        return claimed

    def _claim_payload(self, t_claim_us=None):
        """认领文档：t_claim 用整数微秒——JSON 整数往返精确，CAS 无浮点歧义。"""
        if t_claim_us is None:
            t_claim_us = int(time.time() * 1e6)
        return json.dumps(
            {"status": "claiming", "owner": self.instance_id,
             "t_claim": t_claim_us},
            ensure_ascii=False, separators=(",", ":"))

    def _retries(self, review_id):
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?",
            (f"slow:retry:{review_id}",)).fetchone()
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):
            return 0

    def _bump_retry(self, review_id, error):
        n = self._retries(review_id) + 1
        self.conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"slow:retry:{review_id}", str(n)))
        self.conn.commit()
        return n, f"{type(error).__name__}: {error}"

    def _finalize_failed(self, review, error):
        """有界重试耗尽：经同一短事务走 claim 快照 CAS 写 failed 终态。

        与成功路径共用 `_persist_terminal`——failed 也必须绑定当前持有的
        认领快照（他人已接管时 rowcount=0 → 不覆盖、不冒充终态）。
        """
        self._persist_terminal(
            review, status="failed", detail=None,
            payload={"status": "failed", "error": error, "final": True})

    # ---------- P0-1：终态持久化短事务（一次 commit，claim 快照 CAS） ----------

    def _save_library_sql(self):
        """patterns + pattern_embeddings 的 SQL 回写（不 commit，不自 BEGIN）。"""
        for pid, p in self.library.patterns.items():
            row_id = self._row_id(pid)
            payload = json.dumps(p, ensure_ascii=False,
                                 separators=(",", ":"))
            self.conn.execute(
                "INSERT INTO patterns (pattern_id,camera,signature,name,"
                "detail,state,count,version,payload) VALUES (?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(pattern_id) DO UPDATE SET name=excluded.name,"
                " detail=excluded.detail,state=excluded.state,"
                " count=excluded.count,version=excluded.version,"
                " payload=excluded.payload",
                (row_id, self.camera,
                 json.dumps(p.get("signature", {}), ensure_ascii=False,
                            sort_keys=True),
                 p.get("name"), p.get("detail"), p.get("state", "draft"),
                 int(p.get("count", 0)), int(p.get("version", 1)), payload))
            for modality, emb in (p.get("embs") or {}).items():
                vec = emb.get("c") if isinstance(emb, dict) else None
                if isinstance(vec, list) and vec:
                    self.conn.execute(
                        "INSERT INTO pattern_embeddings"
                        " (pattern_id,modality,centroid,dim,n)"
                        " VALUES (?,?,?,?,?)"
                        " ON CONFLICT(pattern_id,modality) DO UPDATE SET"
                        " centroid=excluded.centroid,dim=excluded.dim,"
                        " n=excluded.n",
                        (row_id, modality, _f32_blob(vec), len(vec),
                         int(emb.get("n", 1))))

    def save_library(self):
        """[兼容保留] 独立回写路径：完整事务纪律 + generation CAS。

        P0-A：
        - 入口守卫——调用方已有未提交事务时 fail-closed，绝不静默提交；
        - BEGIN IMMEDIATE → `_save_library_sql()` → 一次 commit；
        - 任意异常 rollback，返回前保证 `conn.in_transaction is False`；
        - 其他连接绝不可能观察到部分 patterns/embeddings（单事务原子）。
        P0-B：整库写入是主动写入口，必须绑定内存快照的 expected
        generation——BEGIN 后核对数据库 generation 相等才允许写；成功后
        在**同一事务**内 generation+1 并更新 `_library_generation_seen`；
        冲突时 rollback、不覆盖、缓存失效、抛 `SlowGenerationConflict`。
        """
        self._require_clean_connection("save_library")
        expected_generation = self._library_generation_seen \
            if self._library_generation_seen is not None \
            else self._read_generation_sql()
        conn = self.conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            current = self._read_generation_sql()
            if current != expected_generation:
                raise SlowGenerationConflict(
                    f"库代数已变化（期望 {expected_generation}，"
                    f"当前 {current}）：整库回写拒绝覆盖")
            self._save_library_sql()
            self._bump_library_generation_sql()
            conn.commit()
        except Exception as exc:
            conn.rollback()
            if isinstance(exc, SlowGenerationConflict):
                self._library = None            # 旧快照失效，须重新加载
            raise
        self._library_generation_seen = expected_generation + 1

    def _enrich_event_text_sql(self, review_id, *, short_name=None,
                               detail=None):
        """SC-B：semantic_events 空文本补充（不 BEGIN、不 commit）。

        只补与当前 review_id 关联事件的**空/NULL** 文本列（short_name/
        detail）；已有管理员/快路径文本逐字节保留；不创建/删除事件；
        不改 id/时间/类别/区域/规则/状态等任何其他列。
        """
        if not short_name and not detail:
            return 0
        cur = self.conn.execute(
            "UPDATE semantic_events SET"
            " short_name=CASE WHEN (short_name IS NULL OR short_name='')"
            "   AND ? IS NOT NULL AND ?<>'' THEN ? ELSE short_name END,"
            " detail=CASE WHEN (detail IS NULL OR detail='')"
            "   AND ? IS NOT NULL AND ?<>'' THEN ? ELSE detail END"
            " WHERE review_id=?"
            "   AND ((short_name IS NULL OR short_name='')"
            "     OR (detail IS NULL OR detail=''))",
            (short_name, short_name, short_name,
             detail, detail, detail, review_id))
        return cur.rowcount

    def _persist_terminal(self, review, *, status, detail, payload,
                          signature=None, short_name=None):
        """P0-1 终态短事务：patterns/embeddings/segment/空文本一次 commit。

        事务边界：
        - 进入前若连接已存在调用方未提交事务 → fail-closed（SlowPersistenceBusy），
          绝不静默提交外部事务；
        - BEGIN IMMEDIATE → **generation CAS**（数据库当前代数必须等于本实例
          内存库加载快照——旧 worker 不得覆盖管理员刚提交的金标）→
          patterns/embeddings SQL → segment claiming→终态 CAS（绑定
          segment_id+status+owner+t_claim 快照）→ 一次 commit；
        - generation 不等 → rollback、不写任何表、抛 SlowGenerationConflict、
          不覆盖管理员反馈、缓存失效（调用方下一轮重新加载重算）；
        - segment CAS rowcount != 1 → 整个事务 rollback（patterns 不得单独提交）
          并抛 SlowPersistenceConflict；
        - 任意异常 → rollback 全部数据库变化。
        """
        conn = self.conn
        self._require_clean_connection("_persist_terminal")   # P0-A 统一守卫
        expected_generation = self._library_generation_seen \
            if self._library_generation_seen is not None \
            else self._read_generation_sql()
        conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._read_generation_sql()
            if current != expected_generation:
                raise SlowGenerationConflict(
                    f"库代数已变化（期望 {expected_generation}，"
                    f"当前 {current}）：worker 终态写入拒绝覆盖管理员反馈")
            self._save_library_sql()
            cur = conn.execute(
                "UPDATE segments SET signature=?, detail=?, payload=?"
                " WHERE segment_id=?"
                " AND json_extract(payload,'$.status')='claiming'"
                " AND json_extract(payload,'$.owner')=?"
                " AND json_extract(payload,'$.t_claim')=?",
                (json.dumps(signature, ensure_ascii=False, sort_keys=True)
                 if signature is not None else None,
                 detail,
                 json.dumps(payload, ensure_ascii=False,
                            separators=(",", ":")),
                 review["review_id"],
                 review.get("claim_owner"),
                 review.get("claim_t_claim")))
            if cur.rowcount != 1:
                raise SlowPersistenceConflict(
                    f"segment {review['review_id']} 认领快照过期或被接管："
                    "终态 CAS rowcount=0，整事务回滚")
            # SC-B：成功终态时在同一事务内补充 semantic_events 空文本
            # （只补空、绝不覆盖管理员/快路径已有文本；失败即整事务回滚）
            if status in ("matched", "recorded"):
                self._enrich_event_text_sql(
                    review["review_id"], short_name=short_name,
                    detail=detail)
            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            if isinstance(exc, SlowGenerationConflict):
                self._library = None     # 旧快照失效：下一轮必须重新加载
            raise

    @staticmethod
    def _validate_embedding(vec):
        """SC-B 嵌入严格输入：有限实数、拒 bool、维度 1..DIM_MAX。

        使用 patterns.py 的既有上限常量（不复制另一套口径）；非法向量
        返回 None，调用方诚实降级（纯结构匹配），绝不部分写。
        """
        if not isinstance(vec, (list, tuple)) or not vec:
            return None
        if len(vec) > PATTERN_EMBEDDING_DIM_MAX:
            return None
        cleaned = []
        for value in vec:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None
            number = float(value)
            if not math.isfinite(number):
                return None
            cleaned.append(number)
        return cleaned

    def _compute(self, review, *, emb=None, modality=None, provider=None):
        """昂贵阶段（无 DB 写、无长写锁）：签名→内存匹配→嵌入→命名→帧。

        只修改内存 PatternLibrary；其修改仅在 `_persist_terminal` 成功后
        才具备持久意义；失败路径由调用方丢弃内存库。
        嵌入严格校验（非法=降级纯结构）；命名纪律：T2a 命中自命名零 VLM、
        T2b 仅新异一次调用、provider 缺席/undecidable/异常固定降级；
        provider 收到的帧来自安全引用且 ≤3。
        """
        vlm_calls = 0
        naming_fallback = False
        signature = self.signature_for(review)
        result = self.library.match_or_record(
            signature, emb=emb, modality=modality)
        pattern = result["pattern"]
        if result["hit"]:
            self.library.record_hit(pattern, signature["tod"], modality)
            status = "matched"
            detail = pattern.get("name") or f"模式命中 pat-{pattern['id']}"
            payload = {"status": status, "pattern_id": pattern["id"],
                       "sim": round(result["sim"], 4)}
        else:
            status = "recorded"
            detail = None
            payload = {"status": status, "pattern_id": pattern["id"],
                       "sim": round(result["sim"], 4)}
        if emb is not None and modality:
            safe_emb = self._validate_embedding(emb)
            if safe_emb is None:
                payload["embedding"] = "rejected"   # 诚实降级，不部分写
            else:
                self.library.attach_embedding(pattern["id"], safe_emb,
                                              modality)

        named = False
        if status == "recorded" and provider is not None:
            frames, frame_error = self._load_frames(review)
            if frame_error:
                payload["frames"] = frame_error
            frames_b64 = []
            try:
                import base64
                import cv2
                for frame in frames[:MAX_FRAMES]:
                    ok, encoded = cv2.imencode(
                        ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
                    if ok:
                        frames_b64.append(base64.b64encode(
                            encoded.tobytes()).decode("ascii"))
            except Exception:
                frames_b64 = []
            raw = None
            vlm_calls += 1                      # 一次尝试=一次调用
            try:
                raw = provider.understand(
                    "用不超过16个中文字给这段监控活动起一个短名，"
                    "只输出名字；无法判断时只输出 undecidable。",
                    frames_b64[:MAX_FRAMES],
                    context={"camera": self.camera,
                             "signature": signature,
                             "segment_id": review["review_id"]})
            except Exception as exc:
                payload["naming"] = f"provider_error:{type(exc).__name__}"
                naming_fallback = True
            else:
                text = raw.strip() if isinstance(raw, str) else ""
                if text and text.lower() not in ("undecidable", "无法判定"):
                    name = text[:SHORT_NAME_MAX]      # 空值/超长=截断合规
                    self.library.record_name(pattern["id"], name, None, True)
                    detail = name
                    payload["named"] = name
                    named = True
                elif text:
                    payload["naming"] = "undecidable"
                    naming_fallback = True
                else:
                    payload["naming"] = "provider_no_name"
                    naming_fallback = True
        elif status == "recorded":
            payload["naming"] = "pending_naming"   # provider 缺席：诚实降级
            naming_fallback = True

        fallback_name = None
        if status == "recorded" and not named:
            # 诚实降级的模板占位短名（事件列表可读），payload 的 naming
            # 标记保留真实原因；不冒充模型命名
            fallback_name = ("未命名事件 " + str(review["review_id"]))[:
                                                              SHORT_NAME_MAX]
        return {"status": status, "pattern_id": pattern["id"],
                "sim": result["sim"], "named": named,
                "vlm_calls": vlm_calls, "detail": detail,
                "payload": payload, "signature": signature,
                "naming_fallback": naming_fallback,
                "fallback_name": fallback_name}

    def process_one(self, review, *, emb=None, modality=None,
                    provider=None):
        """处理单个闭合审查段：_compute（昂贵阶段）→ _persist_terminal（短事务）。

        返回 {status: matched|recorded, pattern_id, sim, named, vlm_calls}。
        异常向上抛（由 process_pending 计有界重试；认领快照竞争抛
        SlowPersistenceConflict 且不计重试）。
        """
        outcome = self._compute(review, emb=emb, modality=modality,
                                provider=provider)
        self._persist_terminal(review, status=outcome["status"],
                               detail=outcome["detail"],
                               payload=outcome["payload"],
                               signature=outcome["signature"],
                               short_name=(outcome["payload"].get("named")
                                           or outcome.get("fallback_name")
                                           or (outcome["detail"]
                                               if outcome["status"] == "matched"
                                               else None)))
        return {"status": outcome["status"], "pattern_id": outcome["pattern_id"],
                "sim": outcome["sim"], "named": outcome["named"],
                "vlm_calls": outcome["vlm_calls"],
                "naming_fallback": outcome["naming_fallback"]}

    def process_pending(self, *, limit=20, emb_fn=None, provider=None,
                        recover_stale=False, stale_after_s=None):
        """批量处理待办段。返回统计；单段失败只计重试，不中断批。

        P0-1 原子性：每段的 patterns/embeddings/segment 终态（含允许的
        semantic_events 空文本补充）由 `process_one`→`_persist_terminal`
        在**同一短事务**内一次提交；失败即丢弃内存库（懒重载回最后成功段
        状态）——失败段的记忆修改绝不落库、重试不膨胀。认领快照竞争
        （SlowPersistenceConflict/SlowGenerationConflict）不计重试、留待
        下一轮；调用方外层事务未提交时 fail-closed 上抛。
        recover_stale 仅控制"是否接管**异实例**陈旧认领"——默认 False
        （保守）；生产 SlowWorker 显式传 True（真实进程重启后需恢复陈旧
        工作）。快路径真值（review_segments/tracked_objects/semantic_events）
        除允许的空文本列外全程只读。
        """
        stats = {"processed": 0, "matched": 0, "recorded": 0,
                 "vlm_calls": 0, "retried": 0, "failed": 0, "conflict": 0,
                 "fallbacks": 0}
        # P0-A：真实入口守卫——必须在任何查询/认领/写入/昂贵调用之前
        self._require_clean_connection("process_pending")
        # SC-B：陈旧耗尽的终态化在 pending_reviews 收口循环内完成——
        # 以 failed 档计数 delta 计入本轮统计（不重不漏）
        failed_before = self._failed_final_count()
        for review in self.pending_reviews(
                limit, recover_stale=recover_stale,
                stale_after_s=stale_after_s):
            emb = modality = None
            if emb_fn is not None:
                try:
                    emb, modality = emb_fn(review)
                except Exception:
                    emb = modality = None      # 嵌入失败：纯结构匹配降级
            try:
                result = self.process_one(
                    review, emb=emb, modality=modality, provider=provider)
                stats["processed"] += 1
                stats[result["status"]] += 1
                stats["vlm_calls"] += result["vlm_calls"]
                if result.get("naming_fallback"):
                    stats["fallbacks"] += 1
            except SlowPersistenceBusy:
                # fail-closed：调用方外层事务未提交，绝不静默提交
                raise
            except SlowPersistenceConflict:
                # 认领被接管/快照过期：不写终态、不计重试与任何统计，
                # 丢弃内存库（污染不落库），留给下一轮观察
                self._library = None
                stats["conflict"] += 1
            except Exception as error:
                # 幽灵模式防线：失败段可能已改内存（hit/建档）——丢弃内存库，
                # 懒重载回最后成功段状态；污染不落库、重试不膨胀
                self._library = None
                self._bump_retry(review["review_id"], error)
                stats["retried"] += 1
                # SC-B：达上限也**不在此处**终态化——终态化必须同时满足
                # "尝试用尽 + 认领过陈旧阈值"，由 `pending_reviews` 收口
                # 循环按双判据处理；活跃的最后一次尝试保持 claiming。
        # SC-B：收口循环内的陈旧耗尽终态化以计数 delta 计入本轮统计
        stats["failed"] = max(
            stats["failed"],
            self._failed_final_count() - failed_before)
        return stats

    # ---------- 只读观测 ----------

    # ---------- 管理员金标（S3） ----------

    def confirm_pattern(self, pattern_pid, *, name=None, detail=None,
                        misreport=False):
        """管理员反馈 → 模式金标；返回更新后的 pattern 摘要或 None。

        金标高于模型推测但保留历史（DEC-010 纪律）：
        - 改名/补细节：human_confirm → human_samples 计数、达 human_n 晋升
          human-verified；payload 记录最近人工反馈痕迹（可审计）；
        - 误报：audit_result(agree=False) → 降级 draft（计数保留）+ 记录
          misreport 痕迹。绝不自动取消/改写任何管理员规则告警——误报的
          治理动作（改规则/区域）仍归管理员。

        P0-A 单事务合同：目标 pattern 定向更新 + `slow:lib:gen` 递增在
        **同一短事务内一次 commit**；任何一步失败 → rollback 数据库 +
        精确恢复调用前内存库（deepcopy 快照，逐字节等价）+ 连接退出事务
        （in_transaction=False），原异常继续上抛。
        P0-A(R4) BEGIN 边界：`BEGIN IMMEDIATE` 自身也必须在受保护 try 内——
        锁/IO 导致的 BEGIN 失败时内存不得残留任何反馈。
        P0-B generation CAS：取得写锁后先核对数据库 generation 仍等于本实例
        加载快照——两个管理员基于同一旧快照并发提交时，后者必须固定冲突
        失败（不得 last-write-wins）；成功提交后 `_library_generation_seen`
        更新到新代数。
        """
        # 守卫在加载/修改内存与任何写入之前（外层事务 fail-closed）
        self._require_clean_connection("confirm_pattern")
        lib = self.library
        pattern = lib.patterns.get(pattern_pid)
        if pattern is None:
            return None
        if name is not None and not misreport:
            if not isinstance(name, str) or not (0 < len(name) <= 16):
                raise ValueError("name 必须为 1..16 字")

        expected_generation = self._library_generation_seen \
            if self._library_generation_seen is not None \
            else self._read_generation_sql()
        # 内存快照（完整可变状态：patterns + 库序列）
        snapshot_patterns = copy.deepcopy(lib.patterns)
        snapshot_seq = lib.seq

        conn = self.conn
        try:
            conn.execute("BEGIN IMMEDIATE")     # BEGIN 失败也走恢复路径
            current = self._read_generation_sql()
            if current != expected_generation:
                raise SlowGenerationConflict(
                    f"库代数已变化（期望 {expected_generation}，"
                    f"当前 {current}）：管理员反馈拒绝覆盖，请重新加载后重试")
            # 取得写锁且 CAS 通过后，才允许改内存与写库
            if misreport:
                lib.audit_result(pattern_pid, agree=False)
                pattern["last_human_feedback"] = {"misreport": True,
                                                  "at": time.time()}
            else:
                if name is not None:
                    lib.human_confirm(
                        pattern_pid, name=name,
                        detail=detail if isinstance(detail, str)
                        and 0 < len(detail) <= 500 else None)
                else:
                    lib.human_confirm(pattern_pid)
                pattern = lib.patterns.get(pattern_pid)
                pattern["last_human_feedback"] = {
                    "misreport": False, "name": name, "at": time.time()}
            # P1-4：金标只写该 pattern 一行（不整库回写）+ 原子递增库代数
            self._save_one_sql(pattern_pid)
            self._bump_library_generation_sql()
            conn.commit()
        except Exception as exc:
            conn.rollback()
            # 精确恢复内存：BEGIN 失败（未改）或事务内失败（已改）都还原
            lib.patterns = snapshot_patterns
            lib.seq = snapshot_seq
            if isinstance(exc, SlowGenerationConflict):
                self._library = None            # 旧快照失效，须重新加载
            raise
        self._library_generation_seen = expected_generation + 1
        pattern = lib.patterns.get(pattern_pid)
        return {"id": pattern["id"], "name": pattern.get("name"),
                "detail": pattern.get("detail"), "state": pattern["state"],
                "count": pattern.get("count", 0),
                "version": pattern.get("version", 1)}

    def _save_one_sql(self, pattern_pid):
        """单 pattern 定向 SQL（不 BEGIN、不 commit；由调用方持有事务）。"""
        p = self.library.patterns.get(pattern_pid)
        if p is None:
            return
        row_id = self._row_id(pattern_pid)
        payload = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
        self.conn.execute(
            "INSERT INTO patterns (pattern_id,camera,signature,name,"
            "detail,state,count,version,payload) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(pattern_id) DO UPDATE SET name=excluded.name,"
            " detail=excluded.detail,state=excluded.state,"
            " count=excluded.count,version=excluded.version,"
            " payload=excluded.payload",
            (row_id, self.camera,
             json.dumps(p.get("signature", {}), ensure_ascii=False,
                        sort_keys=True),
             p.get("name"), p.get("detail"), p.get("state", "draft"),
             int(p.get("count", 0)), int(p.get("version", 1)), payload))

    def _bump_library_generation_sql(self):
        """原子递增库代数 SQL（不 BEGIN、不 commit；由调用方持有事务）。"""
        self.conn.execute(
            "INSERT INTO meta (key,value) VALUES ('slow:lib:gen','1')"
            " ON CONFLICT(key) DO UPDATE SET"
            " value=CAST(CAST(value AS INTEGER)+1 AS TEXT)")

    @staticmethod
    def library_generation(conn):
        row = conn.execute(
            "SELECT value FROM meta WHERE key='slow:lib:gen'").fetchone()
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):
            return 0

    def pattern_of_event(self, event_id):
        """语义事件 → 其审查段的慢处理档案 → pattern_id；查无返回 None。"""
        row = self.conn.execute(
            "SELECT s.payload, e.camera FROM semantic_events e"
            " JOIN segments s ON s.segment_id = e.review_id"
            " WHERE e.semantic_event_id = ?", (event_id,)).fetchone()
        if row is None:
            return None, None
        try:
            payload = json.loads(row["payload"] or "{}")
        except (TypeError, ValueError):
            payload = {}
        return payload.get("pattern_id"), row["camera"]

    def waterlevel(self):
        """待办水位与失败终态数（S2 接 NVR 后进 /api/health）。

        pending=无档案或仍处 claiming（活跃/陈旧认领）的闭合段。
        """
        open_count = self.conn.execute(
            "SELECT COUNT(*) FROM review_segments r"
            " LEFT JOIN segments s ON s.segment_id = r.review_id"
            " WHERE r.t_end IS NOT NULL AND r.camera=?"
            " AND (s.segment_id IS NULL"
            " OR json_extract(s.payload,'$.status')='claiming')",
            (self.camera,)).fetchone()[0]
        failed = self.conn.execute(
            "SELECT COUNT(*) FROM segments WHERE camera=?"
            " AND json_extract(payload,'$.status')='failed'",
            (self.camera,)).fetchone()[0]
        return {"camera": self.camera, "pending": open_count,
                "failed_final": failed,
                "patterns": len(self.library.patterns)}
