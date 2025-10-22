#!/usr/bin/env python3
"""
挖矿木马检测主程序 - 修复版：正确的层级联动逻辑
L1: 基于内存指标的异常检测 → 触发 L2进程扫描
L2: 基于进程行为的综合检测 → 触发 L3哈希验证
L3: 基于内存哈希的精确匹配检测
"""

import argparse
import json
import re
import time
import sys
import threading
import queue
import os
import signal
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import yaml

# 添加项目根目录到Python路径
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.append(str(PROJECT_ROOT))

# 导入各层检测模块
try:
    from miner_sentinel_l1.src.status_monitor.host_status_judge import HostStatusJudge
    from miner_sentinel_l2.src.detectors.pid_status_scan import PidStatusScanner
    from miner_sentinel_l2.src.utils.system_utils import SystemUtils
    from miner_sentinel_l2.src.models.detection_result import DetectionResult
    from miner_sentinel_l2.src.utils.whitelist_manager import WhitelistManager
    from miner_sentinel_l3.src import listenbitcoin
    from miner_sentinel_l3.src.memory_info import search_in_memory_maps
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保所有依赖的子模块都已正确安装和配置")
    sys.exit(1)


class CryptoJackingDetector:
    """修复版：正确的层级联动逻辑"""

    def __init__(self):
        self.running = False
        self.current_state = "L1_MONITORING"  # 当前状态：L1_MONITORING, L2_SCANNING, L3_VERIFYING

        # 初始化各层检测器
        self.l1_detector = self._init_l1_detector()
        self.l2_detector = self._init_l2_detector()
        self.system_utils = SystemUtils()

        # 检测结果和历史记录
        self.detection_history = []
        self.suspicious_pids = set()  # 可疑进程PID集合

        # 统计信息
        self.stats = {
            'l1_scans': 0,
            'l1_alerts': 0,
            'l2_scans': 0,
            'l2_suspicious': 0,
            'l3_verifications': 0,
            'l3_detections': 0,
            'confirmed_miners': 0
        }


    def _init_l1_detector(self) -> HostStatusJudge:
        """初始化L1内存检测器"""
        return HostStatusJudge()

    def _init_l2_detector(self) -> PidStatusScanner:
        """初始化L2行为检测器"""
        return PidStatusScanner()

    def run_l1_monitoring(self):
        """L1层内存监控 - 检测系统级异常"""
        print("\n\n\n[L1] 启动系统级指标监控...")

        while self.running and self.current_state == "L1_MONITORING":
            try:
                self.stats['l1_scans'] += 1

                # 采集和分析指标
                raw_metrics = self.l1_detector.metrics_collector.collect_all_metrics()
                current_time = time.time()

                # 更新滑动窗口
                for metric_name, value in raw_metrics.items():
                    if metric_name in self.l1_detector.metric_windows:
                        self.l1_detector.metric_windows[metric_name].add_value(value, current_time)

                # 计算聚合值
                windowed_metrics = {}
                for metric_name, window in self.l1_detector.metric_windows.items():
                    if metric_name in ["pgmajfault_per_sec", "pswpin_per_sec", "pswpout_per_sec"]:
                        windowed_metrics[metric_name] = window.calculate_median()
                    else:
                        windowed_metrics[metric_name] = window.calculate_mean()

                # 分析与评分
                total_score, component_scores, category_count = self.l1_detector.analyzer.calculate_total_score(windowed_metrics)
                print('[L1] 当前系统异常总得分：{}， 不同因子得分：{}'.format(total_score, component_scores))

                # 只有当L1检测到系统级异常时才触发L2
                if total_score > self.l1_detector.config['decision']['warning_threshold']:
                    self.stats['l1_alerts'] += 1
                    print(f"🔔 [L1→L2] 系统异常(得分: {total_score})，启动L2进程扫描")
                    self.current_state = "L2_SCANNING"  # 切换到L2状态
                    return  # 退出L1监控，进入L2扫描

                time.sleep(self.l1_detector.config['sampling_interval_seconds'])

            except Exception as e:
                print(f"[L1] 监控出错: {e}")
                time.sleep(self.l1_detector.config['sampling_interval_seconds'])

    def run_l2_scanning(self):
        """L2层进程扫描 - 扫描所有进程寻找可疑行为"""
        print("\n\n\n[L2] 启动全进程扫描...")
        try:
            self.stats['l2_scans'] += 1
            processes = self.system_utils.get_all_processes()
            print('[L2] 总共有{}个进程待确认！'.format(len(processes)))
            for process in processes:
                try:
                    result = self.l2_detector.analyze_process(process.pid)
                    if result and result.status in ["SUSPICIOUS"]:
                        self.suspicious_pids.add(process.pid)
                        print(f"⚠️  [L2可疑] {process.pid}")
                except Exception as e:
                    print(f"[L2] 分析进程 {process.pid} 出错: {e}")
                    continue
            # 如果没有发现可疑进程，返回L1继续监控
            if len(self.suspicious_pids) == 0:
                print("✅ [L2→L1] 未发现可疑进程，返回L1监控")
                self.current_state = "L1_MONITORING"
                return
            else:
                print("⚠️  [L2→L3] 发现可疑进程，启动动态验证，可疑进程为:{}".format(self.suspicious_pids))
                self.current_state = "L3_VERIFYING"

        except Exception as e:
            print(f"[L2] 扫描出错: {e}")
            self.current_state = "L1_MONITORING"
            return

    def _extract_process_memory_to_file(self, pid, output_file):
        """提取进程内存数据到文件，按照结构化格式输出"""
        try:
            total_found = 0
            with open(output_file, 'a', encoding='utf-8') as f:
                # 挖矿相关的模式
                mining_patterns = [
                    r'[0-9a-f]{64}',  # 64字符哈希
                    r'[0-9a-f]{60,68}',  # 接近64字符的哈希
                    r'stratum\+tcp://[^\s]+',  # 矿池地址
                    r'mining\.(notify|submit|authorize)',  # 挖矿协议
                    r'previousblockhash',  # 区块哈希字段
                    r'merkleroot|merkle_root',  # Merkle树根
                    r'[0-9a-f]{16,}',  # 长十六进制字符串
                    r'0000000[0-9a-f]+',  # 比特币哈希特征（前导零）
                ]

                compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in mining_patterns]

                # 读取maps文件
                with open(f"/proc/{pid}/maps", "r") as maps_file:
                    maps_content = maps_file.readlines()

                for line in maps_content:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue

                    addr_range = parts[0]
                    perms = parts[1]
                    pathname = parts[-1] if len(parts) > 5 else "[anonymous]"

                    # 只处理有读权限的区域
                    if 'r' not in perms:
                        continue

                    try:
                        start_addr, end_addr = addr_range.split('-')
                        start_addr = int(start_addr, 16)
                        end_addr = int(end_addr, 16)
                        size = end_addr - start_addr

                        # 读取内存（限制大小）
                        max_read_size = 512 * 1024  # 512KB per region
                        read_size = min(size, max_read_size)

                        with open(f"/proc/{pid}/mem", "rb") as mem_file:
                            mem_file.seek(start_addr)
                            content = mem_file.read(read_size)

                        # 解码为文本
                        text_content = content.decode('utf-8', errors='ignore')

                        # 搜索挖矿相关模式
                        for pattern in compiled_patterns:
                            matches = pattern.findall(text_content)
                            for match in matches:
                                # 结构化输出
                                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                result_line = f"process={pid}, time={current_time}, address={addr_range}, string={match}"
                                f.write(result_line + "\n")
                                total_found += 1

                    except Exception:
                        continue
            print(f"💾 [L3] PID {pid} 内存数据已保存到: {output_file} (找到 {total_found} 个字符串)")
            return True
        except Exception as e:
            print(f"❌ [L3] 提取PID {pid}内存数据失败: {e}")
            return False




    def _cleanup_temp_files(self):
        """清理临时文件"""
        try:
            temp_file = "tmp_suspicious_mem_info.txt"
            os.remove(temp_file)
            print(f"🧹 [L3] 已清理临时文件: {temp_file}")
        except Exception as e:
            print(f"⚠️ [L3] 清理临时文件失败: {e}")


    def run_l3_verification(self):
        """L3层动态验证 - 检测进程内存中是否包含最新比特币区块头字段"""

        print('\n\n\n我们将在15min内检测是否有动态挖矿行为，请耐心等待...')

        try:
            self.stats['l3_verifications'] += 1

            # 监控参数
            monitoring_duration = 15  # 15分钟
            check_interval = 60  # 60秒
            max_checks = 15  # 最多15次检查

            print(f"🔍 [L3] 开始监控 {len(self.suspicious_pids)} 个可疑进程")
            print(f"📊 [L3] 监控参数: {monitoring_duration}分钟, {check_interval}秒间隔, 最多{max_checks}次检查")

            # 为每个可疑进程创建监控记录
            process_monitoring_data = {pid: {'found': False, 'checks': 0} for pid in self.suspicious_pids}

            check_count = 0
            mining_detected = False

            while check_count < max_checks and not mining_detected:
                check_count += 1
                print(f"\n📋 [L3] 第 {check_count} 次检查 (时间: {datetime.now().strftime('%H:%M:%S')})")

                # 在每次检查时获取最新的比特币区块头信息
                try:
                    block_header = listenbitcoin.get_latest_block_header()
                    previous_block_hash = block_header["previous_block_hash"]
                    previous_block_hash_modify = block_header["previous_block_hash_modify"]
                    keywords = [previous_block_hash, previous_block_hash_modify]
                    print(f"✅ [L3] 获取最新区块头成功")
                    print(f"🎯 [L3] 搜索关键词: {', '.join([k[:8] + '...' for k in keywords])}")
                except Exception as e:
                    print(f"⚠️  [L3] 获取最新区块头失败: {e}，跳过本次检查")
                    # 等待后继续下一次检查
                    if check_count < max_checks:
                        time.sleep(check_interval)
                    continue

                for target_pid in list(self.suspicious_pids):  # 使用list避免在迭代时修改
                    if process_monitoring_data[target_pid]['found']:
                        continue

                    process_monitoring_data[target_pid]['checks'] += 1

                    print(
                        f"🔍 [L3] 检查 PID {target_pid} ({process_monitoring_data[target_pid]['checks']}/{max_checks})")

                    # 1) 提取内存数据并保存到文件
                    output_file = f"tmp_suspicious_mem_info.txt"
                    self._extract_process_memory_to_file(target_pid, output_file)

                    # 2) 检查是否匹配关键词
                    match_count = 0
                    with open(output_file, 'r') as f:
                        content = f.read()
                        for keyword in keywords:
                            if keyword in content:
                                # 找到包含关键词的行
                                lines = content.split('\n')
                                for line in lines:
                                    if keyword in line:
                                        print(f"🎯 [L3] 匹配到关键字段: {line}")
                                        match_count += 1
                                        mining_detected = True
                                        break  # 每个关键词只打印第一个匹配行


                # 如果已经发现挖矿进程，提前结束
                if mining_detected:
                    break

                # 等待下一次检查（除了最后一次）
                if check_count < max_checks:
                    print(f"⏳ [L3] 等待 {check_interval} 秒后进行下一次检查... ({check_count}/{max_checks})")
                    time.sleep(check_interval)

            # 3) 检查结果总结
            if mining_detected:
                print(f"\n🎯 [L3结果] 发现挖矿进程！")
            else:
                print(
                    f"\n✅ [L3结果] 所有 {len(self.suspicious_pids)} 个可疑进程经过 {check_count} 次检查，未发现挖矿特征")
                print("✅ [L3排除] 所有可疑进程, 未发现足够挖矿特征")

            # 清理临时文件
            self._cleanup_temp_files()

            # 回到L1监控
            self.current_state = "L1_MONITORING"
            return mining_detected

        except Exception as e:
            print(f"❌ [L3] 验证出错: {e}")
            self.current_state = "L1_MONITORING"
            return False

    def start_monitoring(self):
        """启动综合监控 - 正确的三级联动"""
        if self.running:
            print("监控已在运行中")
            return

        self.running = True
        print("启动三层级挖矿检测监控，L1层（系统状态判断） → L2层（寻找可疑进程） → L3层（内存取证判断）...")
        print('=' * 50)

        try:
            while self.running:
                if self.current_state == "L1_MONITORING":
                    self.run_l1_monitoring()

                elif self.current_state == "L2_SCANNING":
                    self.run_l2_scanning()

                elif self.current_state == "L3_VERIFYING":
                    self.run_l3_verification()

                time.sleep(0.1)  # 避免CPU占用过高

        except KeyboardInterrupt:
            print("\n接收到中断信号，停止监控...")
            self.stop_monitoring()

    def stop_monitoring(self):
        """停止监控"""
        self.running = False
        print("监控已停止")
        print(f"统计信息: {json.dumps(self.stats, indent=2, ensure_ascii=False)}")


def main():
    parser = argparse.ArgumentParser(description='挖矿木马检测主程序')
    parser.add_argument('--monitor', '-m', action='store_true', help='持续监控模式')
    args = parser.parse_args()
    detector = CryptoJackingDetector()
    if args.monitor:
        detector.start_monitoring()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
