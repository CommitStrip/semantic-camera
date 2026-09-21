"""zones.py —— 网格圈选（海康式）：画面划成小正方形，选中格=重点管理区域。"""

import re

DEFAULT_ROWS = 18
DEFAULT_COLS = 22
ZONE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SEVERITIES = {"high", "medium", "low"}


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


def normalize_zones(zones, grid):
    """校验并规范化工作台圈选结果，返回可 JSON 序列化的新对象。

    这是工作台写入 SQLite 和 Monitor 热替换共享的边界。任何坏结构均在进入
    运行线程前 fail-closed，避免一次错误圈选令值守循环逐帧崩溃。
    """
    if not isinstance(zones, list):
        raise ValueError("zones 必须为数组")
    normalized = []
    seen = set()
    for index, zone in enumerate(zones):
        if not isinstance(zone, dict):
            raise ValueError(f"zones[{index}] 必须为对象")
        zone_id = zone.get("id")
        if not isinstance(zone_id, str) or not ZONE_ID_RE.fullmatch(zone_id):
            raise ValueError(
                f"zones[{index}].id 必须为 1-64 位字母、数字、下划线或短横线")
        if zone_id in seen:
            raise ValueError(f"区域 id 重复: {zone_id}")
        seen.add(zone_id)
        name = zone.get("name", zone_id)
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            raise ValueError(f"区域 {zone_id} 的 name 必须为 1-128 位字符串")
        cells = zone.get("cells")
        if not isinstance(cells, list) or not cells:
            raise ValueError(f"区域 {zone_id} 至少选择一个格子")
        if not all(isinstance(cell, int) and not isinstance(cell, bool)
                   and 0 <= cell < grid.size for cell in cells):
            raise ValueError(
                f"区域 {zone_id} 的格子索引必须在 [0,{grid.size - 1}] 内")
        rules = zone.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError(f"区域 {zone_id} 的 rules 必须为数组")
        clean_rules = []
        for rule_index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(
                    f"区域 {zone_id} 的 rules[{rule_index}] 必须为对象")
            cls = rule.get("cls")
            template = rule.get("template", "enter-dwell")
            dwell_s = rule.get("dwell_s", 0)
            severity = rule.get("severity")
            if not isinstance(cls, str) or not cls.strip():
                raise ValueError(f"区域 {zone_id} 的规则缺少 cls")
            if not isinstance(template, str) or not template.strip():
                raise ValueError(f"区域 {zone_id} 的规则缺少 template")
            if not (isinstance(dwell_s, (int, float))
                    and not isinstance(dwell_s, bool) and dwell_s >= 0):
                raise ValueError(f"区域 {zone_id} 的 dwell_s 必须为 ≥0 数值")
            if severity is not None and severity not in SEVERITIES:
                raise ValueError(f"区域 {zone_id} 的 severity 非法")
            clean = dict(rule)
            clean.update({"cls": cls.strip(), "template": template.strip(),
                          "dwell_s": dwell_s})
            clean_rules.append(clean)
        clean_zone = dict(zone)
        clean_zone.update({"id": zone_id, "name": name.strip(),
                           "cells": sorted(set(cells)),
                           "rules": clean_rules})
        normalized.append(clean_zone)
    return normalized
