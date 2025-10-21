#!/usr/bin/env python3
"""
比特币私钥碰撞程序 - 解决大整数问题版
专门处理大整数转换问题
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
        'ecdsa'
    ]
    
    print("正在检查并安装必要的依赖库...")
    
    for package in required_packages:
        try:
            if package == 'base58':
                import base58
            elif package == 'ecdsa':
                import ecdsa
            print(f"✓ {package} 已安装")
        except ImportError:
            print(f"正在安装 {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✓ {package} 安装成功")
            except Exception as e:
                print(f"✗ {package} 安装失败: {e}")
                return False
    
    return True

# 导入所有必要的库
try:
    import numpy as np
    import ecdsa
    import base58
except ImportError:
    print("正在初始化环境并安装依赖...")
    if not auto_install_dependencies():
        print("依赖安装失败，请手动安装必要的库")
        sys.exit(1)
    
    import numpy as np
    import ecdsa
    import base58

class BigIntBitcoinSearcher:
    def __init__(self, target_address):
        self.target_address = target_address
        
        # 设置搜索范围 - 使用字符串表示大整数
        self.start_range_hex = "00000000000000000000000000000000000000000000007ffeffffffffffffff"
        self.end_range_hex = "00000000000000000000000000000000000000000000007fffffffffffffffff"
        
        # 将十六进制字符串转换为整数
        self.start_range = int(self.start_range_hex, 16)
        self.end_range = int(self.end_range_hex, 16)
        
        print(f"搜索范围: {self.start_range_hex} 到 {self.end_range_hex}")
        
        # 计算范围大小
        range_size = self.end_range - self.start_range
        print(f"范围大小: {range_size:,} 个密钥")
        
        if range_size <= 0:
            raise ValueError("无效的搜索范围")
        
        self.found_keys = []
        self.is_running = False
        self.keys_checked = 0
        self.start_time = None
        
        # 使用较少的线程以避免内存问题
        self.num_threads = 4
        self.threads = []
        
        # 线程安全锁
        self.lock = threading.Lock()
        
        print(f"启用 {self.num_threads} 个工作线程")
    
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
    
    def process_range_directly(self, start_key, end_key):
        """直接处理范围，避免大整数转换问题"""
        found_keys = []
        local_checked = 0
        
        # 使用Python的大整数直接计算，不转换为C类型
        current_key = start_key
        
        while current_key < end_key and self.is_running:
            # 每次处理一个密钥
            address = self.private_key_to_address(current_key)
            
            if address == self.target_address:
                found_keys.append((current_key, address))
                print(f"✓ 找到匹配的私钥!")
                print(f"私钥 (hex): {hex(current_key)}")
                print(f"私钥 (decimal): {current_key}")
                print(f"地址: {address}")
            
            current_key += 1
            local_checked += 1
            
            # 每处理10000个密钥更新一次统计
            if local_checked % 10000 == 0:
                with self.lock:
                    self.keys_checked += 10000
                
                if local_checked % 100000 == 0:  # 每10万次显示一次
                    elapsed = time.time() - self.start_time.timestamp()
                    rate = local_checked / elapsed if elapsed > 0 else 0
                    print(f"[直接处理] 已检查: {local_checked:,} 密钥, 速度: {rate:,.0f} 密钥/秒")
        
        # 更新最终计数
        with self.lock:
            self.keys_checked += local_checked % 10000
        
        return found_keys
    
    def worker_thread_simple(self, thread_id, start_key, end_key):
        """简化的工作线程，避免复杂的数据转换"""
        print(f"线程 {thread_id} 启动: {hex(start_key)} 到 {hex(end_key)}")
        
        chunk_size = 1000  # 使用较小的块大小
        local_checked = 0
        thread_start_time = time.time()
        
        current_key = start_key
        
        try:
            while self.is_running and current_key < end_key:
                # 计算当前块的大小
                actual_chunk_size = min(chunk_size, end_key - current_key)
                
                # 直接处理每个密钥，避免批量转换
                found_keys = []
                for i in range(actual_chunk_size):
                    private_key = current_key + i
                    address = self.private_key_to_address(private_key)
                    if address == self.target_address:
                        found_keys.append((private_key, address))
                        print(f"\n[线程 {thread_id}] ✓ 找到匹配的私钥!")
                        print(f"私钥 (hex): {hex(private_key)}")
                        print(f"私钥 (decimal): {private_key}")
                        print(f"地址: {address}")
                
                # 更新统计信息
                with self.lock:
                    self.keys_checked += actual_chunk_size
                    local_checked += actual_chunk_size
                    self.found_keys.extend(found_keys)
                    
                    # 保存找到的密钥
                    for private_key, address in found_keys:
                        self.save_found_key(private_key, address)
                
                current_key += actual_chunk_size
                
                # 定期显示统计信息
                current_time = time.time()
                if current_time - thread_start_time >= 30:  # 每30秒显示一次统计
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
        """开始搜索"""
        print(f"开始搜索...")
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
                target=self.worker_thread_simple,
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
        last_stat_time = time.time()
        last_keys_checked = 0
        
        while self.is_running and any(thread.is_alive() for thread in self.threads):
            current_time = time.time()
            elapsed = current_time - last_stat_time
            
            # 每60秒显示一次总体统计信息
            if elapsed >= 60:
                with self.lock:
                    current_checked = self.keys_checked
                
                keys_since_last = current_checked - last_keys_checked
                rate = keys_since_last / elapsed if elapsed > 0 else 0
                
                total_elapsed = current_time - self.start_time.timestamp()
                total_rate = current_checked / total_elapsed if total_elapsed > 0 else 0
                
                progress = (current_checked / (self.end_range - self.start_range)) * 100
                
                print(f"\n[统计] 已检查: {current_checked:,} 密钥 | "
        f"实时速度: {rate:,.0f} 密钥/秒 | "
                      f"平均速度: {total_rate:,.0f} 密钥/秒 | "
                      f"进度: {progress:.10f}% | "
                      f"找到: {len(self.found_keys)}")
                
                last_stat_time = current_time
                last_keys_checked = current_checked
            
            time.sleep(5)
    
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
    
    print("比特币私钥碰撞程序 - 大整数问题解决版")
    print("=" * 50)
    
    # 创建搜索器
    searcher = BigIntBitcoinSearcher(TARGET_ADDRESS)
    
    try:
        # 开始搜索
        searcher.start_search()
    except KeyboardInterrupt:
        print("\n用户中断搜索")
        searcher.stop()
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
        searcher.stop()

if __name__ == "__main__":
    main()
