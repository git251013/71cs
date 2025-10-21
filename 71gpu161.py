#!/usr/bin/env python3
"""
比特币私钥碰撞程序 - 无进度跟踪版
专注于解决大整数转换问题和最大化性能
"""

import sys
import os
import subprocess
import hashlib
import base58
import threading
import time
from datetime import datetime

# 自动安装所有必要的库
def auto_install_dependencies():
    """自动安装所有必需的依赖库"""
    required_packages = [
        'base58',
        'ecdsa',
        'cupy-cuda11x',
        'pycuda'
    ]
    
    print("正在检查并安装必要的依赖库...")
    
    for package in required_packages:
        try:
            if package == 'base58':
                import base58
            elif package == 'ecdsa':
                import ecdsa
            elif package == 'cupy-cuda11x':
                import cupy
            elif package == 'pycuda':
                import pycuda.autoinit
            print(f"✓ {package} 已安装")
        except ImportError:
            print(f"正在安装 {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✓ {package} 安装成功")
            except Exception as e:
                print(f"✗ {package} 安装失败: {e}")
                return False
    
    # 检查CUDA
    try:
        result = subprocess.run(["nvcc", "--version"], capture_output=True, text=True)
        if "release" in result.stdout:
            print("✓ CUDA 工具包已安装")
        else:
            print("⚠ 请确保CUDA工具包已正确安装")
    except:
        print("⚠ 无法找到nvcc，请检查CUDA安装")
    
    return True

# 导入所有必要的库
try:
    import cupy as cp
    import pycuda.autoinit
    import pycuda.driver as cuda
    from pycuda.compiler import SourceModule
    import numpy as np
    import ecdsa
    import base58
except ImportError:
    print("正在初始化环境并安装依赖...")
    if not auto_install_dependencies():
        print("依赖安装失败，请手动安装必要的库")
        sys.exit(1)
    
    # 重新尝试导入
    import cupy as cp
    import pycuda.autoinit
    import pycuda.driver as cuda
    from pycuda.compiler import SourceModule
    import numpy as np
    import ecdsa
    import base58

class OptimizedBitcoinSearcher:
    def __init__(self, target_address):
        self.target_address = target_address
        
        # 设置搜索范围
        self.start_range_hex = "00000000000000000000000000000000000000000000007ffeffffffffffffff"
        self.end_range_hex = "00000000000000000000000000000000000000000000007fffffffffffffffff"
        
        self.start_range = int(self.start_range_hex, 16)
        self.end_range = int(self.end_range_hex, 16)
        
        # 验证范围
        range_size = self.end_range - self.start_range
        if range_size <= 0:
            raise ValueError("无效的搜索范围")
        
        self.found_keys = []
        self.is_running = False
        self.keys_checked = 0
        self.start_time = None
        
        # 多线程配置
        self.num_threads = self.detect_optimal_thread_count()
        self.threads = []
        
        # 线程安全锁
        self.lock = threading.Lock()
        
        # 统计信息
        self.last_stat_time = None
        self.last_keys_checked = 0
        
        print(f"搜索范围: {self.start_range_hex} 到 {self.end_range_hex}")
        print(f"范围大小: {range_size:,} 个密钥")
        print(f"启用 {self.num_threads} 个工作线程")
    
    def detect_optimal_thread_count(self):
        """检测最优线程数量"""
        try:
            # 获取GPU信息
            device = cuda.Device(0)
            multiprocessors = device.get_attribute(cuda.device_attribute.MULTIPROCESSOR_COUNT)
            
            # 根据GPU计算单元数量确定线程数
            optimal_threads = multiprocessors * 4  # 每个多处理器4个线程
            print(f"GPU多处理器数量: {multiprocessors}")
            
            # 限制最大线程数
            max_threads = min(optimal_threads, 16)  # 最多16个线程
            return max_threads
        except:
            # 如果无法获取GPU信息，使用默认值
            return 8
    
    def private_key_to_address(self, private_key_int):
        """将私钥转换为比特币地址"""
        try:
            # 检查私钥是否在有效范围内
            max_private_key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if private_key_int <= 0 or private_key_int >= max_private_key:
                return None
            
            # 将私钥转换为32字节
            private_key_bytes = private_key_int.to_bytes(32, 'big')
            
            # 使用椭圆曲线secp256k1生成公钥
            sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            public_key_bytes = b'\x04' + vk.to_string()  # 未压缩公钥
            
            # SHA256哈希
            sha256_hash = hashlib.sha256(public_key_bytes).digest()
            
            # RIPEMD160哈希
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
            
            # 添加版本字节 (0x00 用于主网)
            version = b'\x00'
            payload = version + ripemd160_hash
            
            # 计算校验和
            checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            
            # 生成最终地址
            address_bytes = payload + checksum
            address = base58.b58encode(address_bytes).decode('ascii')
            
            return address
            
        except Exception as e:
            return None
    
    def process_chunk_safely(self, start_key, chunk_size):
        """安全处理数据块，避免大整数问题"""
        found_keys = []
        
        # 将大整数范围分解为可管理的小块
        max_chunk_size = 10000  # 限制每个块的大小
        actual_chunk_size = min(chunk_size, max_chunk_size)
        
        try:
            # 使用NumPy处理小范围，避免大整数问题
            keys_np = np.arange(start_key, start_key + actual_chunk_size, dtype=np.uint64)
            
            # 逐个处理密钥
            for i in range(len(keys_np)):
                private_key = int(keys_np[i])
                address = self.private_key_to_address(private_key)
                if address == self.target_address:
                    found_keys.append((private_key, address))
                    
        except Exception as e:
            # 如果NumPy处理失败，使用纯Python处理
            print(f"NumPy处理失败，使用纯Python: {e}")
            for i in range(actual_chunk_size):
                private_key = start_key + i
                address = self.private_key_to_address(private_key)
                if address == self.target_address:
                    found_keys.append((private_key, address))
        
        return found_keys
    
    def worker_thread(self, thread_id, start_key, end_key):
        """工作线程函数"""
        print(f"线程 {thread_id} 启动: {hex(start_key)} 到 {hex(end_key)}")
        
        chunk_size = 10000  # 每次处理10000个密钥
        local_checked = 0
        thread_start_time = time.time()
        
        current_key = start_key
        
        try:
            while self.is_running and current_key < end_key:
                # 计算当前块的大小
                actual_chunk_size = min(chunk_size, end_key - current_key)
                
                # 处理当前块
                found_keys = self.process_chunk_safely(current_key, actual_chunk_size)
                
                # 更新统计信息
                with self.lock:
                    self.keys_checked += actual_chunk_size
                    local_checked += actual_chunk_size
                    
                    # 处理找到的密钥
                    for private_key, address in found_keys:
                        self.found_keys.append((private_key, address))
                        self.save_found_key(private_key, address)
                        print(f"\n[线程 {thread_id}] ✓ 找到匹配的私钥!")
                        print(f"私钥 (hex): {hex(private_key)}")
                        print(f"私钥 (decimal): {private_key}")
                        print(f"地址: {address}")
                
                current_key += actual_chunk_size
                
                # 定期显示统计信息
                current_time = time.time()
                if current_time - thread_start_time >= 10:  # 每10秒显示一次统计
                    elapsed = current_time - thread_start_time
                    rate = local_checked / elapsed if elapsed > 0 else 0
                    print(f"[线程 {thread_id}] 已检查: {local_checked:,} 密钥, 速度: {rate:,.0f} 密钥/秒")
                    thread_start_time = current_time
                
                # 检查是否需要停止
                if not self.is_running:
                    break
                    
        except Exception as e:
            print(f"[线程 {thread_id}] 错误: {e}")
        
        print(f"[线程 {thread_id}] 完成，检查了 {local_checked:,} 个密钥")
    
    def start_search(self):
        """开始多线程搜索"""
        print(f"开始多线程搜索...")
        print(f"目标地址: {self.target_address}")
        
        self.start_time = datetime.now()
        self.is_running = True
        self.keys_checked = 0
        
        # 计算每个线程的范围
        total_range = self.end_range - self.start_range
        range_per_thread = total_range // self.num_threads
        
        print(f"分配范围给 {self.num_threads} 个线程...")
        
        # 创建并启动工作线程
        for i in range(self.num_threads):
            thread_start = self.start_range + i * range_per_thread
            thread_end = thread_start + range_per_thread if i < self.num_threads - 1 else self.end_range
            
            thread = threading.Thread(
                target=self.worker_thread,
                args=(i, thread_start, thread_end)
            )
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
        
        # 启动统计信息线程
        stat_thread = threading.Thread(target=self.statistics_monitor)
        stat_thread.daemon = True
        stat_thread.start()
        
        try:
            # 等待所有线程完成
            for thread in self.threads:
                thread.join()
                
        except KeyboardInterrupt:
            print("\n收到中断信号，正在停止所有线程...")
            self.is_running = False
            
            # 等待线程安全退出
            for thread in self.threads:
                thread.join(timeout=2)
        
        finally:
            self.is_running = False
            self.show_final_statistics()
    
    def statistics_monitor(self):
        """统计信息监控线程"""
        self.last_stat_time = time.time()
        self.last_keys_checked = 0
        
        while self.is_running and any(thread.is_alive() for thread in self.threads):
            current_time = time.time()
            elapsed = current_time - self.last_stat_time
            
            # 每30秒显示一次总体统计信息
            if elapsed >= 30:
                with self.lock:
                    current_checked = self.keys_checked
                
                keys_since_last = current_checked - self.last_keys_checked
                rate = keys_since_last / elapsed if elapsed > 0 else 0
                
                total_elapsed = current_time - self.start_time.timestamp()
                total_rate = current_checked / total_elapsed if total_elapsed > 0 else 0
                
                progress = (current_checked / (self.end_range - self.start_range)) * 100
                
                print(f"\n[统计] 已检查: {current_checked:,} 密钥 | "
                      f"实时速度: {rate:,.0f} 密钥/秒 | "
                      f"平均速度: {total_rate:,.0f} 密钥/秒 | "
                      f"进度: {progress:.8f}% | "
                      f"找到: {len(self.found_keys)}")
                
                self.last_stat_time = current_time
                self.last_keys_checked = current_checked
            
            time.sleep(1)
    
    def show_final_statistics(self):
        """显示最终统计信息"""
        total_time = (datetime.now() - self.start_time).total_seconds()
        
        print("\n" + "="*60)
        print("搜索完成!")
        print("="*60)
        print(f"总运行时间: {total_time:.2f} 秒")
        print(f"检查的密钥数量: {self.keys_checked:,}")
        
        if total_time > 0:
            print(f"平均速度: {self.keys_checked/total_time:,.0f} 密钥/秒")
        
        print(f"找到的匹配数量: {len(self.found_keys)}")
        
        if self.found_keys:
            print("\n找到的私钥:")
            for i, (private_key, address) in enumerate(self.found_keys):
                print(f"{i+1}. 私钥 (hex): {hex(private_key)}")
                print(f"   私钥 (decimal): {private_key}")
                print(f"   地址: {address}")
        
        print("="*60)
    
    def save_found_key(self, private_key, address):
        """保存找到的私钥到文件"""
        filename = f"found_keys_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'a') as f:
            f.write(f"私钥 (hex): {hex(private_key)}\n")
            f.write(f"私钥 (decimal): {private_key}\n")
            f.write(f"地址: {address}\n")
            f.write(f"发现时间: {datetime.now().isoformat()}\n")
            f.write("-" * 50 + "\n")
        
        print(f"结果已保存到: {filename}")
    
    def stop(self):
        """停止搜索"""
        self.is_running = False

def main():
    # 目标比特币地址
    TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
    
    print("比特币私钥碰撞程序 - 无进度跟踪版")
    print("=" * 50)
    
    # 显示系统信息
    try:
        device = cuda.Device(0)
        gpu_name = device.name()
        gpu_memory = device.total_memory() // (1024**3)
        multiprocessors = device.get_attribute(cuda.device_attribute.MULTIPROCESSOR_COUNT)
        print(f"GPU: {gpu_name}")
        print(f"GPU内存: {gpu_memory} GB")
        print(f"多处理器: {multiprocessors}")
    except Exception as e:
        print(f"GPU信息: {e}")
        print("使用CPU多线程模式")
    
    # 创建搜索器
    searcher = OptimizedBitcoinSearcher(TARGET_ADDRESS)
    
    try:
        # 开始搜索
        searcher.start_search()
    except KeyboardInterrupt:
        print("\n用户中断搜索")
        searcher.stop()
    except Exception as e:
        print(f"错误: {e}")
        searcher.stop()

if __name__ == "__main__":
    main()
