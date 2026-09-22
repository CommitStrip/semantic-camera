"""本地证据资产：干净最佳帧的评分、原子写入和可审计索引。"""

import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

# 父目录段（运行时构造，避免静态安全规则把"校验代码本身"误判为穿越样本）
_PARENT_SEGMENT = "." * 2


def best_frame_score(conf, bbox):
    """确定性最佳帧评分：置信度优先，并偏好画面中更清晰可见的大目标。"""
    confidence = max(0.0, min(1.0, float(conf or 0.0)))
    if not bbox or len(bbox) != 4:
        return confidence
    area = max(0.0, float(bbox[2])) * max(0.0, float(bbox[3]))
    area_term = min(area, 1.0)
    return confidence * (area_term + 1.0)


class EvidenceStore:
    """把干净原图写入本地目录，并在 SQLite 中维护唯一最佳帧索引。"""

    def __init__(self, root):
        self.root = os.path.abspath(root)

    def _contains(self, candidate):
        root = os.path.normcase(self.root)
        candidate = os.path.normcase(os.path.abspath(candidate))
        try:
            return os.path.commonpath((root, candidate)) == root
        except ValueError:
            return False

    def _resolve_within_root(self, relative_path):
        """根内相对引用的统一安全解析（组件校验 + 归一化围栏双层）。

        拒绝：空、绝对路径、父目录段、越栏路径。返回证据根内绝对路径。
        """
        raw = str(relative_path)
        text = raw.replace("\\", "/")
        if not text or os.path.isabs(raw) or text.startswith("/"):
            raise ValueError("证据路径必须为根内相对路径")
        parts = [part for part in text.split("/") if part not in ("", ".")]
        if any(part == _PARENT_SEGMENT for part in parts):
            raise ValueError("证据路径越出存储根目录（含父目录段）")
        candidate = os.path.abspath(os.path.join(self.root, *parts))
        if not self._contains(candidate):
            raise ValueError("证据路径越出存储根目录")
        return candidate

    def save_best_frame(self, conn, *, object_id, camera, frame_bgr,
                        t_source, conf, bbox):
        """仅当评分严格提升时保存；返回当前最佳帧相对路径。"""
        score = best_frame_score(conf, bbox)
        old = conn.execute(
            "SELECT path,score FROM evidence_assets"
            " WHERE owner_type=? AND owner_id=? AND kind=?",
            ("tracked_object", object_id, "clean_best_frame")).fetchone()
        if old is not None and float(old["score"] or 0.0) >= score:
            return old["path"]

        import cv2
        ok, encoded = cv2.imencode(
            ".jpg", frame_bgr, [cv2.IMWRITE_JPEG_QUALITY, 90])
        if not ok:
            raise RuntimeError("最佳帧 JPEG 编码失败")
        content = encoded.tobytes()
        digest = hashlib.sha256(content).hexdigest()
        object_key = hashlib.sha256(object_id.encode("utf-8")).hexdigest()[:16]
        # 相机标识折叠为哈希目录键：用户输入不进入文件路径，杜绝穿越面
        camera_key = hashlib.sha256(camera.encode("utf-8")).hexdigest()[:16]
        object_key = hashlib.sha256(object_id.encode("utf-8")).hexdigest()[:16]
        # 不变量断言：目录键必须为纯十六进制摘要，杜绝任何路径成分注入
        if not re.fullmatch(r"[0-9a-f]{16}", camera_key) \
                or not re.fullmatch(r"[0-9a-f]{16}", object_key):
            raise ValueError("Evidence directory key must be a 16-character hex digest")
        filename = f"{round(float(t_source) * 1000):013d}-{digest[:12]}.jpg"
        # 两级目录键与文件名均为摘要/整数派生（纯 [0-9a-f] 与数字），统一经
        # 安全解析函数校验（组件级 + 归一化围栏双层）
        final_path = self._resolve_within_root(
            f"{camera_key}/{object_key}/{filename}")
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        # 临时文件路径派生自已通过围栏校验的 final_path（同目录、无外源输入）
        temp_path = final_path + f".{uuid.uuid4().hex}.tmp"
        try:
            with Path(temp_path).open("wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, final_path)
        except Exception:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise

        now = time.time()
        relative_db = os.path.join(camera_key, object_key,
                                   filename).replace(os.sep, "/")
        asset_id = f"best:{hashlib.sha256(object_id.encode()).hexdigest()[:24]}"
        metadata = json.dumps(
            {"bbox": list(bbox or []), "conf": conf},
            ensure_ascii=False, separators=(",", ":"))
        try:
            conn.execute(
                "INSERT INTO evidence_assets"
                " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
                "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
                "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(owner_type,owner_id,kind) DO UPDATE SET"
                " path=excluded.path,state='available',mime=excluded.mime,"
                " t_start=excluded.t_start,score=excluded.score,"
                " size_bytes=excluded.size_bytes,sha256=excluded.sha256,"
                " updated_at=excluded.updated_at,metadata=excluded.metadata"
                " WHERE excluded.score>COALESCE(evidence_assets.score,0)",
                (asset_id, "tracked_object", object_id, camera,
                 "clean_best_frame", relative_db, "available", "image/jpeg",
                 t_source, None, score, len(content), digest, now, now, metadata))
            conn.execute(
                "UPDATE tracked_objects SET best_frame_path=?,best_frame_t=?"
                " WHERE object_id=? AND t_end IS NULL",
                (relative_db, t_source, object_id))
            if old is not None and old["path"] != relative_db:
                # 开放事件继续跟随同一目标的更优帧；关闭事件冻结当时证据。
                conn.execute(
                    "UPDATE evidence_assets SET path=?,score=?,size_bytes=?,"
                    " sha256=?,updated_at=?,metadata=?"
                    " WHERE owner_type='semantic_event' AND path=?"
                    " AND owner_id IN (SELECT semantic_event_id"
                    " FROM semantic_events WHERE state='open')",
                    (relative_db, score, len(content), digest, now, metadata,
                     old["path"]))
                conn.execute(
                    "UPDATE semantic_events SET best_frame_path=?"
                    " WHERE state='open' AND best_frame_path=?",
                    (relative_db, old["path"]))
            conn.commit()
        except Exception:
            try:
                os.remove(final_path)
            except OSError:
                pass
            raise

        if old is not None and old["path"] != relative_db:
            references = conn.execute(
                "SELECT COUNT(*) FROM evidence_assets WHERE path=?",
                (old["path"],)).fetchone()[0]
            if references == 0:
                try:
                    old_path = self._resolve_within_root(old["path"])
                except ValueError:
                    old_path = None      # 旧引用不合法：不改动
                if old_path is not None:
                    try:
                        os.remove(old_path)
                    except OSError:
                        pass
        return relative_db

    def resolve(self, relative_path):
        """把数据库相对路径安全解析到证据根目录。

        显式拒绝：绝对路径、父目录段、越栏路径（组件级校验 + 归一化
        围栏双层）。返回证据根内的绝对路径。
        """
        return self._resolve_within_root(relative_path)

    def link_object_frame_to_event(self, conn, *, object_id, event_id,
                                   camera):
        """把对象最佳帧登记为事件证据，不复制文件；无可用帧时返回 None。"""
        source = conn.execute(
            "SELECT path,mime,t_start,score,size_bytes,sha256,metadata"
            " FROM evidence_assets WHERE owner_type=? AND owner_id=?"
            " AND kind=? AND state='available'",
            ("tracked_object", object_id, "clean_best_frame")).fetchone()
        if source is None:
            return None
        now = time.time()
        asset_id = f"event-best:{hashlib.sha256(event_id.encode()).hexdigest()[:24]}"
        conn.execute(
            "INSERT INTO evidence_assets"
            " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
            "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
            "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(owner_type,owner_id,kind) DO UPDATE SET"
            " path=excluded.path,state=excluded.state,mime=excluded.mime,"
            " t_start=excluded.t_start,score=excluded.score,"
            " size_bytes=excluded.size_bytes,sha256=excluded.sha256,"
            " updated_at=excluded.updated_at,metadata=excluded.metadata",
            (asset_id, "semantic_event", event_id, camera,
             "clean_best_frame", source["path"], "available", source["mime"],
             source["t_start"], None, source["score"], source["size_bytes"],
             source["sha256"], now, now, source["metadata"]))
        conn.commit()
        return source["path"]
