"""Immutable, bounded original-crop archives. Not yet wired into the runtime.

Use only from a slow evidence worker, never the capture/L1 thread. Each archive
atomically contains lossless PNG pixels and provenance; no SQLite migration or
existing asset deletion. The root is a dedicated, trusted local-user directory.
"""
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import zipfile

import numpy as np


class CropEvidenceError(Exception):
    """Fixed diagnostic code; never include paths or raw OS errors in the UI."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


# sc.crop/v1 core identity (C-141 §1): these ten keys keep their exact v1
# semantics; every one of them is still required.
_V1_KEYS = {"camera_id", "run_id", "config_version", "material_id", "frame_id",
            "crop_id", "t_capture_ms", "timestamp_kind", "source_size", "bbox_px"}
# sc.crop/v2 optional supplements. Identity keys complete the frozen 9-key
# identity; the segment keys are the bounded extension block.
_V2_IDENTITY_KEYS = {"window_id", "branch", "slot", "frame_seq"}
_V2_SEGMENT_KEYS = {"participants", "relation_candidates", "uncertainty", "box_notes"}
_V2_KEYS = _V2_IDENTITY_KEYS | _V2_SEGMENT_KEYS
_ALL_KEYS = _V1_KEYS | _V2_KEYS
_SEGMENT_BYTES_LIMIT = 8192
_PARTICIPANTS_LIMIT = 16
_CANDIDATES_LIMIT = 16
_BOX_NOTES_LIMIT = 8
_SHORT_TEXT_LIMIT = 256
_RESERVED_INDEX_DIR = "index"


def _schema_for(meta):
    """sc.crop/v2 exactly when a v2 key is present; pure v1 shape stays v1."""
    if any(key in meta for key in _V2_KEYS):
        return "sc.crop/v2"
    return "sc.crop/v1"


def _provenance(value):
    if not isinstance(value, dict) or not _V1_KEYS <= set(value) \
            or not set(value) <= _ALL_KEYS:
        raise CropEvidenceError("invalid_provenance")
    result = json.loads(json.dumps(value, allow_nan=False))
    for key in ("camera_id", "run_id", "crop_id", "timestamp_kind"):
        if not isinstance(result[key], str) or not 0 < len(result[key]) <= 256:
            raise CropEvidenceError("invalid_provenance")
    for key in ("config_version", "material_id"):
        identity = result[key]
        if not ((type(identity) is int and identity >= 0) or
                (type(identity) is str and 0 < len(identity) <= 256)):
            raise CropEvidenceError("invalid_provenance")
    for key in ("frame_id",):
        if type(result[key]) is not int or result[key] < 0:
            raise CropEvidenceError("invalid_provenance")
    t = result["t_capture_ms"]
    if type(t) not in (int, float) or not math.isfinite(t) or t < 0:
        raise CropEvidenceError("invalid_provenance")
    size, box = result["source_size"], result["bbox_px"]
    if not isinstance(size, list) or len(size) != 2 or any(
            type(x) is not int or x <= 0 for x in size):
        raise CropEvidenceError("invalid_provenance")
    if not isinstance(box, list) or len(box) != 4 or any(type(x) is not int for x in box):
        raise CropEvidenceError("invalid_provenance")
    x1, y1, x2, y2 = box
    if not (0 <= x1 < x2 <= size[0] and 0 <= y1 < y2 <= size[1]):
        raise CropEvidenceError("invalid_provenance")
    # --- sc.crop/v2 optional supplements: validated only when present; v1
    # dicts never reach this block, so v1 semantics above stay untouched. ---
    if "window_id" in result:
        window = result["window_id"]
        if not ((type(window) is int and window >= 0) or
                (type(window) is str and 0 < len(window) <= _SHORT_TEXT_LIMIT)):
            raise CropEvidenceError("invalid_provenance")
    if "branch" in result and result["branch"] not in ("panorama", "local"):
        raise CropEvidenceError("invalid_provenance")
    if "slot" in result and result["slot"] not in ("previous", "current", "next"):
        raise CropEvidenceError("invalid_provenance")
    if "frame_seq" in result and (type(result["frame_seq"]) is not int
                                  or result["frame_seq"] < 0):
        raise CropEvidenceError("invalid_provenance")
    if "participants" in result:
        participants = result["participants"]
        if (not isinstance(participants, list)
                or len(participants) > _PARTICIPANTS_LIMIT
                or any(not isinstance(item, dict) for item in participants)):
            raise CropEvidenceError("invalid_provenance")
    if "relation_candidates" in result:
        candidates = result["relation_candidates"]
        if not isinstance(candidates, list) or len(candidates) > _CANDIDATES_LIMIT:
            raise CropEvidenceError("invalid_provenance")
        for candidate in candidates:
            if not isinstance(candidate, dict) or "score" not in candidate \
                    or "vocab_id" not in candidate:
                raise CropEvidenceError("invalid_provenance")
            score = candidate["score"]
            if type(score) not in (int, float) or not math.isfinite(score):
                raise CropEvidenceError("invalid_provenance")
            vocab = candidate["vocab_id"]
            if not isinstance(vocab, str) or not 0 < len(vocab) <= _SHORT_TEXT_LIMIT:
                raise CropEvidenceError("invalid_provenance")
    if "uncertainty" in result and not isinstance(result["uncertainty"], dict):
        raise CropEvidenceError("invalid_provenance")
    if "box_notes" in result:
        notes = result["box_notes"]
        if (not isinstance(notes, list) or len(notes) > _BOX_NOTES_LIMIT
                or any(not isinstance(note, str)
                       or not 0 < len(note) <= _SHORT_TEXT_LIMIT for note in notes)):
            raise CropEvidenceError("invalid_provenance")
    # Bounded extension block: serialized size cap (NaN/±Inf were already
    # rejected by the allow_nan=False round trip above).
    extras = {key: result[key] for key in _V2_SEGMENT_KEYS if key in result}
    if extras:
        payload = json.dumps(extras, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(payload) > _SEGMENT_BYTES_LIMIT:
            raise CropEvidenceError("invalid_provenance")
    return result


class CropEvidenceStore:
    """One archive per content identity; explicit capacity failure, no eviction.

    A cross-process exclusive lock guards quota accounting and publication.
    A crash can leave its lock: fail busy until manually investigated, never
    guess stale ownership. Read returns PNG bytes, not an arbitrary path.
    """

    def __init__(self, root, *, max_assets=4096, max_total_bytes=256*1024*1024,
                 max_asset_bytes=8*1024*1024, max_pixels=4_000_000):
        limits = (max_assets, max_total_bytes, max_asset_bytes, max_pixels)
        if any(type(x) is not int or x <= 0 for x in limits):
            raise ValueError("positive integer limits required")
        self.root = Path(root).absolute()
        self.max_assets, self.max_total_bytes, self.max_asset_bytes, self.max_pixels = limits
        self._check_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self._check_root()

    def _check_root(self):
        for path in (self.root, *self.root.parents):
            if (path.is_symlink() or (path.exists() and
                    getattr(path.lstat(), "st_file_attributes", 0) &
                    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))):
                raise CropEvidenceError("unsafe_root")
        if self.root.exists() and not self.root.is_dir():
            raise CropEvidenceError("unsafe_root")

    def _read_file(self, path):
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > self.max_asset_bytes:
            raise CropEvidenceError("corrupt")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not os.path.samestat(before, opened):
                raise CropEvidenceError("corrupt")
            content = stream.read(self.max_asset_bytes + 1)
            after = os.fstat(stream.fileno())
        current = path.lstat()
        if (not os.path.samestat(opened, current) or not stat.S_ISREG(current.st_mode)
                or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                or (after.st_size, after.st_mtime_ns) != (current.st_size, current.st_mtime_ns)
                or len(content) != opened.st_size):
            raise CropEvidenceError("corrupt")
        return content

    def save(self, frame_bgr, provenance):
        """Accept original pixels only; caller must not pass an SR/annotated image."""
        try:
            meta = _provenance(provenance)
        except (TypeError, ValueError, OverflowError):
            raise CropEvidenceError("invalid_provenance") from None
        box = meta["bbox_px"]
        if (not isinstance(frame_bgr, np.ndarray) or frame_bgr.dtype != np.uint8
                or frame_bgr.ndim != 3 or frame_bgr.shape[2] != 3
                or frame_bgr.shape[:2] != (box[3]-box[1], box[2]-box[0])
                or frame_bgr.shape[0]*frame_bgr.shape[1] > self.max_pixels):
            raise CropEvidenceError("invalid_pixels")
        import cv2
        ok, encoded = cv2.imencode(".png", frame_bgr.copy())
        if not ok:
            raise CropEvidenceError("encode_failed")
        png = encoded.tobytes()
        metadata = {"schema": _schema_for(meta), "kind": "original_crop",
                    "provenance": meta, "png_sha256": hashlib.sha256(png).hexdigest()}
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(zipfile.ZipInfo("metadata.json"), json.dumps(metadata, ensure_ascii=False,
                              sort_keys=True, separators=(",", ":"), allow_nan=False))
            archive.writestr(zipfile.ZipInfo("original.png"), png)
        content = output.getvalue()
        if len(content) > self.max_asset_bytes:
            raise CropEvidenceError("asset_budget")
        asset_id = hashlib.sha256(content).hexdigest()
        self._check_root()
        lock = self.root / ".write-lock"
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise CropEvidenceError("busy") from None
        except OSError:
            raise CropEvidenceError("write_failed") from None
        temporary = None
        try:
            final = self.root / (asset_id + ".crop")
            if final.exists():
                self.read(asset_id)  # verify, never silently replace a corrupt archive
                return asset_id
            count = total = 0
            with os.scandir(self.root) as entries:
                for entry in entries:
                    if entry.name == ".write-lock":
                        continue
                    # Reserved directory of the C-141 evidence worker's
                    # persistent index; never counted as quota or evidence.
                    # A symlink/reparse "index" entry still falls through and
                    # is rejected below.
                    if entry.name == _RESERVED_INDEX_DIR and entry.is_dir(follow_symlinks=False) \
                            and not (getattr(entry.stat(follow_symlinks=False),
                                             "st_file_attributes", 0) &
                                     getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)):
                        continue
                    if (not re.fullmatch(r"[0-9a-f]{64}\.crop", entry.name)
                            or not entry.is_file(follow_symlinks=False)):
                        raise CropEvidenceError("unsafe_root")
                    count += 1
                    total += entry.stat(follow_symlinks=False).st_size
                    if count >= self.max_assets or total + len(content) > self.max_total_bytes:
                        raise CropEvidenceError("capacity")
            if total + len(content) > self.max_total_bytes:
                raise CropEvidenceError("capacity")
            fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=self.root)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, final)  # atomic no-clobber; no unsafe rename fallback
            return asset_id
        except OSError:
            raise CropEvidenceError("write_failed") from None
        finally:
            if temporary is not None:
                os.unlink(temporary)
            os.close(lock_fd)
            lock.unlink()

    def read(self, asset_id):
        """Return verified {metadata, png}; fixed missing/corrupt diagnostics."""
        if not isinstance(asset_id, str) or not re.fullmatch(r"[0-9a-f]{64}", asset_id):
            raise CropEvidenceError("invalid_id")
        self._check_root()
        try:
            content = self._read_file(self.root / (asset_id + ".crop"))
            if hashlib.sha256(content).hexdigest() != asset_id:
                raise CropEvidenceError("corrupt")
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                infos = archive.infolist()
                if (len(infos) != 2 or {x.filename for x in infos} != {"metadata.json", "original.png"}
                        or any(x.compress_type != zipfile.ZIP_STORED for x in infos)
                        or any(x.file_size > self.max_asset_bytes for x in infos)):
                    raise CropEvidenceError("corrupt")
                metadata = json.loads(archive.read("metadata.json"))
                png = archive.read("original.png")
            # v1 archives keep reading unchanged; v2 is the key-superset form.
            # The stored schema label must match the provenance shape exactly.
            if (metadata.get("schema") not in ("sc.crop/v1", "sc.crop/v2")
                    or metadata["kind"] != "original_crop"
                    or hashlib.sha256(png).hexdigest() != metadata["png_sha256"]
                    or not png.startswith(b"\x89PNG\r\n\x1a\n")):
                raise CropEvidenceError("corrupt")
            validated = _provenance(metadata["provenance"])
            if metadata["schema"] != _schema_for(validated):
                raise CropEvidenceError("corrupt")
            if (len(png) < 33 or png[12:16] != b"IHDR"
                    or struct.unpack(">I", png[8:12])[0] != 13):
                raise CropEvidenceError("corrupt")
            width, height = struct.unpack(">II", png[16:24])
            box = metadata["provenance"]["bbox_px"]
            if (width <= 0 or height <= 0 or width*height > self.max_pixels
                    or (width, height) != (box[2]-box[0], box[3]-box[1])):
                raise CropEvidenceError("corrupt")
            import cv2
            image = cv2.imdecode(np.frombuffer(png, dtype=np.uint8), cv2.IMREAD_COLOR)
            if image is None or image.shape != (height, width, 3):
                raise CropEvidenceError("corrupt")
            return {"metadata": metadata, "png": png}
        except FileNotFoundError:
            raise CropEvidenceError("missing") from None
        except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile):
            raise CropEvidenceError("corrupt") from None
