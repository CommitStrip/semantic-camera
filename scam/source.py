"""source.py —— 相机源接入（薄封装 vus FrameSource，P1 完善）。

职责：RTSP/文件/相机的统一拉流与断流守护；
P0 仅提供接口形状，P1 接入 vus FrameSource 实装。
"""


class CameraSource:
    """一路相机源：拉帧供门控/检测；断流自动重连（指数退避）。"""

    def __init__(self, camera_id, source_url):
        self.camera_id = camera_id
        self.source_url = source_url
        self.frame = None            # 最近一帧（BGR ndarray）
        self.ok = False

    def read(self):
        """读取一帧；P1 实装（封装 vus RTSPSource）。"""
        raise NotImplementedError("P1: 接入 vus FrameSource")
