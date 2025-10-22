import json
import os
import time
from pathlib import Path
from typing import Dict

import yaml

from .collector import MetricsCollector
from .analyzer import PressureAnalyzer
from .window import TimeSlidingWindow


class HostStatusJudge:
    """挖矿行为检测器（支持 CPU PSI & CPU 利用率）"""

    def __init__(self):
        self.config = self._load_config()
        self.metrics_collector = MetricsCollector()
        self.analyzer = PressureAnalyzer(self.config)

        # 初始化滑动窗口（新增 cpu_some_avg10、cpu_utilization）
        self.monitoring_metrics = [
            "memory_usage",
            "cache_hit_ratio",
            "some_avg10",
            "full_avg10",         # memory PSI
            "pgmajfault_per_sec",
            "pswpin_per_sec",
            "pswpout_per_sec",
            "cpu_some_avg10",                   # NEW: CPU PSI (some.avg10)
            "cpu_utilization"                   # NEW: 全局 CPU 利用率 0~1
        ]
        self.metric_windows = {
            metric: TimeSlidingWindow(self.config.get("time_window_seconds", 60))
            for metric in self.monitoring_metrics
        }
        self.last_alert_time = 0.0
        self.consecutive_healthy_samples = 0

    def _load_config(self):
        config_path = os.path.join(Path(__file__).parent.parent, 'config/monitoring_rules.yaml')
        print(config_path)
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
        return config
