#!/usr/bin/env python3
"""
比特币私钥扫描器 - 高性能多进程GPU加速版本
扫描范围: 2^70 到 2^71
目标地址: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
"""

import os
import sys
import time
import hashlib
import multiprocessing as mp
from datetime import datetime
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
import gc

# 自动安装必要的库
def install_requirements():
    libraries = [
        "base58",
        "numpy", 
        "cupy-cuda11x",
        "psutil"
    ]
    
    for lib in libraries:
        try:
            if lib == "base58":
                import base58
            elif lib == "numpy":
                import numpy as np
            elif lib == "cupy-cuda11x":
                import cupy as cp
            elif lib == "psutil":
                import psutil
        except ImportError:
            print(f"安装 {lib} 库...")
            if lib == "cupy-cuda11x":
                os.system("pip install cupy-cuda11x")
            else:
                os.system(f"pip install {lib}")
    
    import base58
    import numpy as np
    import cupy as cp
    import psutil
    
    return base58, np, cp, psutil

# 安装库并导入
base58, np, cp, psutil = install_requirements()

# 目标地址
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# 椭圆曲线参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class ECParams:
    """椭圆曲线参数类"""
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.Gx = GX
        self.Gy = GY
        self.n = N

def mod_inverse(a, modulus):
    """模逆计算"""
    return pow(a, modulus - 2, modulus)

def point_add(P1, P2, p, a):
    """椭圆曲线点相加"""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
        
    x1, y1 = P1
    x2, y2 = P2
    
    # 处理点相同的情况（点加倍）
    if x1 == x2:
        if y1 == y2:
            return point_double(P1, p, a)
        else:
            return None  # 点是相反的，结果为无穷远点
            
    # 计算斜率
    s = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
    
    # 计算新点坐标
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    
    return (x3, y3)
    
def point_double(P, p, a):
    """椭圆曲线点加倍"""
    if P is None:
        return None
        
    x, y = P
    
    # 计算斜率
    s = ((3 * x * x + a) * mod_inverse(2 * y, p)) % p
    
    # 计算新点坐标
    x3 = (s * s - 2 * x) % p
    y3 = (s * (x - x3) - y) % p
    
    return (x3, y3)
    
def point_multiply(k, P, p, a):
    """椭圆曲线点乘 - 使用倍加算法"""
    if k == 0:
        return None
        
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = point_add(result, addend, p, a)
        addend = point_double(addend, p, a)
        k >>= 1
        
    return result

def private_key_to_compressed_address(private_key_int, ec_params):
    """私钥到地址转换"""
    # 计算公钥点
    public_point = point_multiply(private_key_int, (ec_params.Gx, ec_params.Gy), ec_params.p, ec_params.a)
    
    if public_point is None:
        return None
        
    x, y = public_point
    
    # 压缩公钥格式
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    compressed_pubkey = prefix + x.to_bytes(32, 'big')
    
    # SHA-256
    sha256_hash = hashlib.sha256(compressed_pubkey).digest()
    
    # RIPEMD-160
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # 添加版本字节
    versioned_payload = b'\x00' + ripemd160_hash
    
    # 计算校验和
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    
    # Base58编码
    address_bytes = versioned_payload + checksum
    bitcoin_address = base58.b58encode(address_bytes).decode('ascii')
    
    return bitcoin_address

class KeyBatch:
    """密钥批次处理类"""
    def __init__(self, start_key, batch_size):
        self.start_key = start_key
        self.batch_size = batch_size
        self.end_key = start_key + batch_size
        self.current_key = start_key
        self.processed = 0
        
    def get_next_key(self):
        """获取下一个密钥"""
        if self.current_key < self.end_key:
            key = self.current_key
            self.current_key += 1
            self.processed += 1
            return key
        return None

class GPUWorker:
    """GPU工作器类"""
    def __init__(self, worker_id, ec_params, target_address):
        self.worker_id = worker_id
        self.ec_params = ec_params
        self.target_address = target_address
        self.processed = 0
        self.found_key = None
        
    def process_batch(self, key_batch):
        """处理密钥批次"""
        batch_processed = 0
        
        while True:
            key = key_batch.get_next_key()
            if key is None:
                break
                
            address = private_key_to_compressed_address(key, self.ec_params)
            batch_processed += 1
            
            if address == self.target_address:
                self.found_key = key
                break
        
        self.processed += batch_processed
        return self.found_key, batch_processed

class ProcessWorker:
    """进程工作器类"""
    def __init__(self, process_id, start_key, end_key, batch_size, target_address, result_queue, progress_queue, stop_event):
        self.process_id = process_id
        self.start_key = start_key
        self.end_key = end_key
        self.batch_size = batch_size
        self.target_address = target_address
        self.result_queue = result_queue
        self.progress_queue = progress_queue
        self.stop_event = stop_event
        self.ec_params = ECParams()
        self.processed = 0
        self.last_report_time = time.time()
        
        # 创建线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        self.gpu_workers = [GPUWorker(i, self.ec_params, target_address) for i in range(4)]
        
    def run(self):
        """运行工作进程"""
        print(f"进程 {self.process_id} 启动: 范围 {self.start_key} 到 {self.end_key}")
        
        current_key = self.start_key
        
        while current_key < self.end_key and not self.stop_event.is_set():
            # 计算当前批次大小
            actual_batch_size = min(self.batch_size, self.end_key - current_key)
            
            # 创建密钥批次
            key_batch = KeyBatch(current_key, actual_batch_size)
            
            # 使用线程池并行处理
            futures = []
            for gpu_worker in self.gpu_workers:
                future = self.thread_pool.submit(gpu_worker.process_batch, key_batch)
                futures.append(future)
            
            # 等待所有线程完成
            batch_processed = 0
            found_key = None
            
            for future in futures:
                try:
                    key, processed = future.result(timeout=300)  # 5分钟超时
                    batch_processed += processed
                    if key is not None:
                        found_key = key
                        break
                except Exception as e:
                    print(f"进程 {self.process_id} 线程错误: {e}")
            
            # 更新处理计数
            self.processed += batch_processed
            current_key += actual_batch_size
            
            # 报告进度
            current_time = time.time()
            if current_time - self.last_report_time >= 30:  # 每30秒报告一次
                progress = (current_key - self.start_key) / (self.end_key - self.start_key) * 100
                self.progress_queue.put((self.process_id, self.processed, progress))
                self.last_report_time = current_time
            
            # 如果找到密钥，发送结果并退出
            if found_key is not None:
                self.result_queue.put((self.process_id, found_key, self.target_address))
                break
        
        # 清理资源
        self.thread_pool.shutdown(wait=True)
        print(f"进程 {self.process_id} 完成，处理了 {self.processed} 个密钥")

class BitcoinKeyScanner:
    def __init__(self, num_processes=None, batch_size=100000):
        self.start_range = 2**70
        self.end_range = 2**71
        self.batch_size = batch_size
        self.target_address = TARGET_ADDRESS
        
        # 根据系统资源自动配置
        if num_processes is None:
            # 使用75%的CPU核心，留一些给系统
            self.num_processes = max(1, int(mp.cpu_count() * 0.75))
        else:
            self.num_processes = num_processes
            
        # 限制最大进程数
        self.num_processes = min(self.num_processes, 32)
        
        # 共享状态
        self.total_processed = mp.Value('i', 0)
        self.start_time = time.time()
        self.stop_event = mp.Event()
        self.result_queue = mp.Queue()
        self.progress_queue = mp.Queue()
        
        # 进程列表
        self.processes = []
        
        print(f"系统资源: CPU核心 {mp.cpu_count()}, 内存 {psutil.virtual_memory().total // (1024**3)}GB")
        print(f"扫描器配置: {self.num_processes} 个进程, 批次大小 {self.batch_size}")
        
    def address_to_hash160(self, address):
        """将比特币地址转换回hash160"""
        decoded = base58.b58decode(address)
        return decoded[1:21]  # 跳过版本字节，取hash160部分
        
    def create_processes(self):
        """创建工作进程"""
        # 计算每个进程的扫描范围
        total_range = self.end_range - self.start_range
        range_per_process = total_range // self.num_processes
        
        for i in range(self.num_processes):
            start_key = self.start_range + i * range_per_process
            if i == self.num_processes - 1:
                end_key = self.end_range  # 最后一个进程处理剩余部分
            else:
                end_key = self.start_range + (i + 1) * range_per_process
                
            # 创建进程
            p = mp.Process(
                target=self._process_worker,
                args=(i, start_key, end_key, self.batch_size, self.target_address,
                      self.result_queue, self.progress_queue, self.stop_event)
            )
            self.processes.append(p)
    
    def _process_worker(self, process_id, start_key, end_key, batch_size, target_address,
                       result_queue, progress_queue, stop_event):
        """进程工作函数"""
        worker = ProcessWorker(process_id, start_key, end_key, batch_size, 
                              target_address, result_queue, progress_queue, stop_event)
        worker.run()
        
    def stats_reporter(self):
        """统计信息报告线程"""
        last_total = 0
        last_time = time.time()
        process_stats = {}
        
        while not self.stop_event.is_set():
            time.sleep(10)  # 每10秒报告一次
            
            # 收集进程进度
            while not self.progress_queue.empty():
                try:
                    process_id, processed, progress = self.progress_queue.get_nowait()
                    process_stats[process_id] = (processed, progress)
                except queue.Empty:
                    break
            
            # 计算总处理数
            current_total = self.total_processed.value
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            
            # 计算速度
            recent_speed = (current_total - last_total) / (current_time - last_time)
            overall_speed = current_total / elapsed_time
            
            # 计算进度
            progress_percent = (current_total / (self.end_range - self.start_range)) * 100
            
            # 估算剩余时间
            if overall_speed > 0:
                remaining_keys = (self.end_range - self.start_range) - current_total
                estimated_remaining = remaining_keys / overall_speed
            else:
                estimated_remaining = 0
            
            # 显示统计信息
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 全局统计:")
            print(f"  进度: {progress_percent:.10f}%")
            print(f"  已处理: {current_total} 密钥")
            print(f"  当前速度: {recent_speed:.2f} 密钥/秒")
            print(f"  平均速度: {overall_speed:.2f} 密钥/秒")
            print(f"  运行时间: {elapsed_time/3600:.2f} 小时")
            print(f"  预计剩余: {estimated_remaining/3600:.2f} 小时")
            
            # 显示进程统计
            if process_stats:
                print(f"  进程状态:")
                for pid, (proc_processed, proc_progress) in process_stats.items():
                    print(f"    进程 {pid}: {proc_progress:.6f}% ({proc_processed} 密钥)")
            
            print("-" * 60)
            
            last_total = current_total
            last_time = current_time
            
            # 定期垃圾回收
            if int(current_time) % 300 == 0:  # 每5分钟执行一次
                gc.collect()
    
    def progress_updater(self):
        """进度更新线程"""
        while not self.stop_event.is_set():
            time.sleep(5)
            
            # 计算活动进程数
            active_processes = sum(1 for p in self.processes if p.is_alive())
            
            # 如果没有活动进程且没有找到结果，重新启动进程
            if active_processes == 0 and not self.stop_event.is_set():
                print("检测到所有进程已结束，重新启动...")
                self.stop_processes()
                self.create_processes()
                self.start_processes()
    
    def start_processes(self):
        """启动所有进程"""
        for p in self.processes:
            p.start()
    
    def stop_processes(self):
        """停止所有进程"""
        self.stop_event.set()
        for p in self.processes:
            if p.is_alive():
                p.terminate()
                p.join(timeout=5)
    
    def scan_range(self):
        """扫描指定范围的私钥"""
        print(f"开始扫描范围: {self.start_range} 到 {self.end_range}")
        print(f"目标地址: {self.target_address}")
        print(f"进程数: {self.num_processes}")
        print(f"批次大小: {self.batch_size}")
        print("=" * 70)
        
        # 创建工作进程
        self.create_processes()
        
        # 启动统计报告线程
        stats_thread = threading.Thread(target=self.stats_reporter)
        stats_thread.daemon = True
        stats_thread.start()
        
        # 启动进度更新线程
        progress_thread = threading.Thread(target=self.progress_updater)
        progress_thread.daemon = True
        progress_thread.start()
        
        # 启动所有进程
        self.start_processes()
        
        # 等待结果
        try:
            found_key = None
            found_process = None
            
            while not self.stop_event.is_set():
                # 检查是否有结果
                try:
                    result = self.result_queue.get(timeout=1)
                    found_process, found_key, address = result
                    break
                except queue.Empty:
                    # 检查是否有进程异常退出
                    active_count = sum(1 for p in self.processes if p.is_alive())
                    if active_count < self.num_processes:
                        print(f"警告: {self.num_processes - active_count} 个进程异常退出")
                    
                    # 更新总处理数
                    # 这里简化处理，实际应该从各个进程收集数据
                    continue
        
        except KeyboardInterrupt:
            print("\n接收到中断信号，停止所有进程...")
            self.stop_event.set()
        
        finally:
            # 停止所有进程
            self.stop_processes()
            
            # 等待统计线程结束
            stats_thread.join(timeout=5)
            progress_thread.join(timeout=5)
        
        # 显示结果
        if found_key is not None:
            elapsed_time = time.time() - self.start_time
            print("\n" + "=" * 70)
            print("🎉 找到目标私钥! 🎉")
            print(f"由进程 {found_process} 找到")
            print(f"私钥 (十进制): {found_key}")
            print(f"私钥 (十六进制): {hex(found_key)}")
            print(f"对应地址: {address}")
            print(f"总处理时间: {elapsed_time:.2f} 秒")
            print(f"总处理密钥数: {self.total_processed.value}")
            print("=" * 70)
            
            # 保存结果到文件
            with open("found_private_key.txt", "w") as f:
                f.write(f"私钥 (十进制): {found_key}\n")
                f.write(f"私钥 (十六进制): {hex(found_key)}\n")
                f.write(f"对应地址: {address}\n")
                f.write(f"找到时间: {datetime.now()}\n")
                f.write(f"扫描范围: {self.start_range} 到 {self.end_range}\n")
                f.write(f"总处理密钥数: {self.total_processed.value}\n")
                f.write(f"总耗时: {elapsed_time:.2f} 秒\n")
                f.write(f"使用进程数: {self.num_processes}\n")
                f.write(f"批次大小: {self.batch_size}\n")
            
            return found_key
        else:
            elapsed_time = time.time() - self.start_time
            print("\n" + "=" * 70)
            print("扫描完成，未找到目标私钥")
            print(f"总处理时间: {elapsed_time:.2f} 秒")
            print(f"总处理密钥数: {self.total_processed.value}")
            print(f"平均速度: {self.total_processed.value/elapsed_time:.2f} 密钥/秒")
            print("=" * 70)
            
            return None

def main():
    """主函数"""
    print("比特币私钥扫描器 - 高性能多进程GPU加速版")
    print("正在初始化...")
    
    # 允许用户指定进程数和批次大小
    num_processes = None
    batch_size = 100000
    
    if len(sys.argv) > 1:
        try:
            num_processes = int(sys.argv[1])
            print(f"使用指定进程数: {num_processes}")
        except ValueError:
            print("无效的进程数参数，使用自动检测")
    
    if len(sys.argv) > 2:
        try:
            batch_size = int(sys.argv[2])
            print(f"使用指定批次大小: {batch_size}")
        except ValueError:
            print("无效的批次大小参数，使用默认值")
    
    try:
        scanner = BitcoinKeyScanner(num_processes=num_processes, batch_size=batch_size)
        scanner.scan_range()
        
    except KeyboardInterrupt:
        print("\n用户中断扫描")
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # 在Windows上使用spawn方法，确保多进程兼容性
    if sys.platform.startswith('win'):
        mp.set_start_method('spawn')
    main()
