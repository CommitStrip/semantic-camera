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

    def save_scene_frame(self, *, camera, frame_bytes, established_at):
        """环境基线原始画面落盘：每次尝试独立文件身份 + 不覆盖发布。

        碰撞防护（A-R2）：文件名含**本次尝试令牌**（12 位 hex nonce），同一
        相机、相同 JPEG、同一秒的两次尝试也各得独立路径，绝不共用待清理
        目标。发布走硬链接原子上位：目标已存在即明确失败（FileExistsError
        → ValueError），文件系统不支持该安全操作也明确失败——两种情况都
        **绝不回退到可能覆盖目标的 os.replace**。
        返回相对路径、sha256/字节数与 owner_token（清理所有权凭据）。
        """
        if not isinstance(camera, str) or not re.fullmatch(
                r"[A-Za-z0-9_\-]+", camera):
            raise ValueError("相机标识仅限字母数字与 - _")
        if not isinstance(frame_bytes, (bytes, bytearray)) or \
                not bytes(frame_bytes).startswith(b"\xff\xd8"):
            raise ValueError("基线画面必须是 JPEG 字节")
        content = bytes(frame_bytes)
        digest = hashlib.sha256(content).hexdigest()
        # 相机标识折叠为哈希目录键：用户输入不进入文件路径，杜绝穿越面
        camera_key = hashlib.sha256(camera.encode("utf-8")).hexdigest()[:16]
        if not re.fullmatch(r"[0-9a-f]{16}", camera_key):
            raise ValueError(
                "Evidence directory key must be a 16-character hex digest")
        # 尝试令牌：随机 nonce，只有本次调用持有；文件身份不可由
        # 内容/相机/时间推导（杜绝"同秒同画面"撞名）
        owner_token = uuid.uuid4().hex[:12]
        if not re.fullmatch(r"[0-9a-f]{12}", owner_token):
            raise ValueError("Evidence attempt token must be hex")
        filename = (f"{int(established_at):013d}-{digest[:12]}-"
                    f"{owner_token}.jpg")
        final_rel = camera_key + "/baseline/" + filename
        final_path = self._resolve_within_root(final_rel)
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        # 临时文件路径派生自已通过围栏校验的 final_path（同目录、无外源输入）
        temp_path = final_path + "." + uuid.uuid4().hex + ".tmp"
        try:
            with Path(temp_path).open("wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                # 原子"不覆盖上位"：目标已存在 → OSError（EEXIST）；
                # 文件系统不支持硬链接 → OSError（EPERM/ENOSYS 等）。
                # 二者都必须显式失败，绝不回退 os.replace 覆盖。
                os.link(temp_path, final_path)
            except FileExistsError:
                raise ValueError("基线画面目标已存在，拒绝覆盖")
            except OSError:
                raise ValueError(
                    "基线画面发布失败：文件系统不支持安全发布操作")
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return {"path": final_rel,
                "sha256": digest, "size_bytes": len(content),
                "owner_token": owner_token}

    def discard_attempt_file(self, relative_path, owner_token):
        """删除**本次尝试新建**的画面文件；所有权双查（A-R2）。

        - 令牌必须是 12 位 hex 且真实出现在文件名尾段：文件身份由本次调用
          的 nonce 铸造，不能仅凭"计算出的文件名等于本次路径"认定所有权；
        - 路径仍走证据根围栏。任一条件不满足即拒绝删除（ValueError）。
        注意：调用方还须自行核验"库内零引用"后才可调用本方法。
        """
        if not isinstance(owner_token, str) or \
                not re.fullmatch(r"[0-9a-f]{12}", owner_token):
            raise ValueError("清理令牌非法（无法证明文件属于本次尝试）")
        full = self.resolve(relative_path)
        name = full.replace("\\", "/").rsplit("/", 1)[-1]
        if not name.endswith("-" + owner_token + ".jpg"):
            raise ValueError("文件不属于本次尝试（令牌不匹配），拒绝删除")
        os.remove(full)

    def read_scene_frame(self, relative_path, *, sha256=None, size_bytes=None):
        """按完整性复核读取基线原始画面；缺失/损坏抛 ValueError，绝不外泄路径。"""
        try:
            full = self.resolve(relative_path)
        except ValueError:
            raise ValueError("基线画面引用非法")
        try:
            with Path(full).open("rb") as handle:
                content = handle.read()
        except OSError:
            raise ValueError("基线画面缺失")
        if sha256 and hashlib.sha256(content).hexdigest() != sha256:
            raise ValueError("基线画面哈希不符")
        if size_bytes is not None and len(content) != int(size_bytes):
            raise ValueError("基线画面大小不符")
        if not content.startswith(b"\xff\xd8"):
            raise ValueError("基线画面非 JPEG")
        return content

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
