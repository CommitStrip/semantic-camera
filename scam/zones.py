"""zones.py —— 网格圈选（海康式）：画面划成小正方形，选中格=重点管理区域。"""

DEFAULT_ROWS = 18
DEFAULT_COLS = 22


class Grid:
    """网格：rows×cols 个小方格，索引 = row * cols + col（行优先）。

    检测判定：目标中心点的归一化坐标 → 所在格索引 → 格子被选中即在
    重点管理区域内（无需点在多边形内的几何计算）。
    """

    def __init__(self, rows=DEFAULT_ROWS, cols=DEFAULT_COLS):
        if not (isinstance(rows, int) and rows >= 4 and
                isinstance(cols, int) and cols >= 4):
            raise ValueError("grid 行列必须为 ≥4 的整数")
        self.rows = rows
        self.cols = cols
        self.size = rows * cols

    def cell_of(self, nx, ny):
        """归一化坐标 (0..1) → 格索引；越界自动收拢到边界格。"""
        col = min(self.cols - 1, max(0, int(nx * self.cols)))
        row = min(self.rows - 1, max(0, int(ny * self.rows)))
        return row * self.cols + col

    def contains(self, idx, cells):
        """idx 是否在选中格集合（set/list 均可）中。"""
        return idx in cells


def bbox_center_cell(grid, bbox):
    """检测框（归一化 [x,y,w,h]）中心点 → 格索引。"""
    cx = bbox[0] + bbox[2] / 2.0
    cy = bbox[1] + bbox[3] / 2.0
    return grid.cell_of(cx, cy)
