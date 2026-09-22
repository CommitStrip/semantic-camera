"""scam.slow_worker —— S2：慢系统有界后台接线（Linux NVR）。

独立守护线程周期消费 S1（SlowCore）：快路径永不等待（本线程异常全隔离，
SQLite 各自连接）；积压由固定批上限+轮间隔节流（固定策略降级，不堆并发）；
公开队列水位、最近错误、pattern hit 与 VLM 调用计数（/api/health slow 段）；
关机有界：批间检查停机事件、join 有超时，未完成事实留在水位里如实可见
（S1 幂等水位保证下轮续跑），不吞也不丢。
"""

import threading
import time

from .db import connect
from .slow_core import SlowCore


class SlowWorker:
    """每相机一个 SlowCore 的串行轮询 worker（单线程，天然无库竞争）。"""

    def __init__(self, db_path, camera_ids, *, interval_s=30.0,
                 batch_limit=20, provider=None, embedder=None,
                 frame_loader=None, stop_event=None):
        self.db_path = db_path
        self.camera_ids = list(camera_ids)
        self.interval_s = max(1.0, float(interval_s))
        self.batch_limit = int(batch_limit)
        self.provider = provider
        # V-JEPA 段嵌入（可选注入）：缺席/帧缺失/解码失败一律降级纯结构
        # 匹配（slow_core.emb_fn 契约），绝不阻塞慢处理。
        self.embedder = embedder
        # SC-B：三帧证据加载器（安全引用过滤在 SlowCore 内完成；None=内建
        # 安全解码）。loader 只接收已过滤引用，绝不接裸路径。
        self.frame_loader = frame_loader
        self.stop_event = stop_event or threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        # 生命周期累计计数 + 最近一轮信息（snapshot 只读这些，不碰库）
        self.totals = {"processed": 0, "matched": 0, "recorded": 0,
                       "vlm_calls": 0, "retried": 0, "failed": 0, "runs": 0}
        self.last_error = None          # 固定格式：异常类型名，不含正文/路径
        self.last_run_ts = None
        self.cameras_state = {}

    # ---------- 生命周期 ----------

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return False
        self._thread = threading.Thread(
            target=self._run, name="scam-slow-worker", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout=10.0):
        """有界关机：批间退出；超时返回 False（未完成事实留在水位，不吞）。"""
        self.stop_event.set()
        if self._thread is None:
            return True
        self._thread.join(timeout=timeout)
        return not self._thread.is_alive()

    def _run(self):
        conn = connect(self.db_path)
        cores = {cid: SlowCore(conn, camera=cid,
                               frame_loader=self.frame_loader)
                 for cid in self.camera_ids}
        # 库代数：金标（HTTP 线程单行写）递增代数；轮首发现变化即重载，
        # 吸收金标后再继续累积——避免批末全量回写覆盖管理员改名
        gen_seen = {cid: SlowCore.library_generation(conn)
                    for cid in self.camera_ids}
        try:
            while not self.stop_event.wait(self.interval_s):
                for cid, core in cores.items():
                    gen_now = SlowCore.library_generation(conn)
                    if gen_now != gen_seen[cid]:
                        core._library = None       # 懒重载
                        gen_seen[cid] = gen_now
                self._round(cores, conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _round(self, cores, conn):
        """单轮：逐相机消费一批；任何异常隔离为 last_error，下一轮继续。"""
        def emb_fn(review):
            """段代表帧 → (嵌入向量, 模态)；无帧/无 embedder → (None, None)。"""
            if self.embedder is None:
                return None, None
            frame, modality = cores[review["camera"]].embedding_input(review) \
                if review["camera"] in cores else (None, None)
            if frame is None:
                return None, None
            return self.embedder.embed([frame]), modality

        try:
            for cid, core in cores.items():
                stats = core.process_pending(
                    limit=self.batch_limit, provider=self.provider,
                    emb_fn=emb_fn, recover_stale=True)
                with self._lock:
                    for key in ("processed", "matched", "recorded",
                                "vlm_calls", "retried", "failed"):
                        self.totals[key] += stats.get(key, 0)
                    self.totals["runs"] += 1
                    self.cameras_state[cid] = stats
            with self._lock:
                self.last_run_ts = time.time()
                self.last_error = None
        except Exception as exc:
            # 异常正文可能含主机/磁盘细节——只披露类型名（项目纪律）。
            with self._lock:
                self.last_error = type(exc).__name__

    # ---------- 观测（/api/health slow 段数据源） ----------

    def snapshot(self):
        """水位与计数快照；水位查询失败结构化降级，绝不让 health 500。"""
        with self._lock:
            payload = {
                "enabled": True,
                "embedding": "on" if self.embedder is not None
                else "structural_only",
                "cameras": {cid: dict(stats)
                            for cid, stats in self.cameras_state.items()},
                "totals": dict(self.totals),
                "last_error": self.last_error,
                "last_run_ts": self.last_run_ts,
            }
        levels = {}
        try:
            conn = connect(self.db_path)
            try:
                for cid in self.camera_ids:
                    core = SlowCore(conn, camera=cid)
                    levels[cid] = core.waterlevel()
            finally:
                conn.close()
        except Exception as exc:
            payload["waterlevel_error"] = type(exc).__name__
            return payload
        pending = sum(item["pending"] for item in levels.values())
        payload["waterlevel"] = levels
        payload["pending_total"] = pending
        payload["backlogged"] = pending > 100   # 固定降级阈值：可见但不扩批
        return payload
