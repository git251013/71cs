#!/usr/bin/env python3
"""
比特币地址碰撞搜索工具
目标地址: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
搜索范围: 2^70.6999 到 2^70.9999
"""

import os
import sys
import time
import multiprocessing as mp
from multiprocessing import Process, Queue, Value, Lock
import hashlib
import random
import base58
import threading

# 尝试自动安装必要的库
def install_packages():
    packages = ['ecdsa', 'base58']
    for package in packages:
        try:
            __import__(package)
        except ImportError:
            print(f"正在安装 {package}...")
            os.system(f"{sys.executable} -m pip install {package}")

install_packages()

# 导入必要的库
try:
    import ecdsa
    from ecdsa import SigningKey, SECP256k1
    import base58
except ImportError as e:
    print(f"导入库失败: {e}")
    sys.exit(1)

# 目标地址
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

# 搜索范围 (2^70.6999 到 2^70.9999)
START_EXPONENT = 70.6999
END_EXPONENT = 70.9999

# 计算实际的搜索范围
START_RANGE = int(2 ** START_EXPONENT)
END_RANGE = int(2 ** END_EXPONENT)

print(f"搜索范围: 2^{START_EXPONENT} 到 2^{END_EXPONENT}")
print(f"实际范围: {START_RANGE} 到 {END_RANGE}")
print(f"搜索空间大小: {END_RANGE - START_RANGE:,}")

class KeyGenerator:
    """密钥生成器，确保不重复"""
    
    def __init__(self, start_range, end_range):
        self.start_range = start_range
        self.end_range = end_range
        self.range_size = end_range - start_range
        self.generated_indices = set()
        self.lock = Lock()
        
    def get_random_key_index(self):
        """获取不重复的随机密钥索引"""
        with self.lock:
            if len(self.generated_indices) >= self.range_size * 0.99:
                # 如果已经生成了99%的密钥，重新开始（避免无限循环）
                self.generated_indices.clear()
                
            while True:
                index = random.randint(self.start_range, self.end_range)
                if index not in self.generated_indices:
                    self.generated_indices.add(index)
                    return index

def private_key_to_address(private_key_int):
    """将私钥整数转换为比特币压缩地址"""
    try:
        # 将整数转换为32字节的十六进制字符串
        private_key_hex = hex(private_key_int)[2:].zfill(64)
        
        # 创建签名密钥
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        
        # 获取验证密钥（公钥）
        vk = sk.get_verifying_key()
        
        # 压缩公钥
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        compressed_pubkey = bytes.fromhex('02' if y % 2 == 0 else '03') + x.to_bytes(32, 'big')
        
        # SHA-256哈希
        sha256_hash = hashlib.sha256(compressed_pubkey).digest()
        
        # RIPEMD-160哈希
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # 添加版本字节（0x00 for mainnet）
        versioned_hash = b'\x00' + ripemd160_hash
        
        # 双重SHA-256哈希用于校验和
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # 组合并转换为base58
        binary_address = versioned_hash + checksum
        address = base58.b58encode(binary_address).decode('ascii')
        
        return address, private_key_hex
        
    except Exception as e:
        return None, None

def worker(worker_id, key_generator, found_flag, counter, save_results, queue):
    """工作进程函数"""
    print(f"工作进程 {worker_id} 启动")
    
    keys_checked = 0
    start_time = time.time()
    
    while not found_flag.value:
        try:
            # 获取不重复的私钥索引
            private_key_int = key_generator.get_random_key_index()
            
            # 生成地址
            address, private_key_hex = private_key_to_address(private_key_int)
            
            if address is None:
                continue
                
            keys_checked += 1
            
            # 更新计数器
            with counter.get_lock():
                counter.value += 1
            
            # 每10000次检查打印进度
            if keys_checked % 10000 == 0:
                elapsed = time.time() - start_time
                rate = keys_checked / elapsed if elapsed > 0 else 0
                print(f"进程 {worker_id}: 已检查 {keys_checked:,} 个密钥, 速率: {rate:.2f} 密钥/秒")
            
            # 检查是否找到目标地址
            if address == TARGET_ADDRESS:
                print(f"\n!!! 找到目标地址 !!!")
                print(f"进程: {worker_id}")
                print(f"私钥 (十六进制): {private_key_hex}")
                print(f"私钥 (十进制): {private_key_int}")
                print(f"地址: {address}")
                
                # 设置找到标志
                found_flag.value = True
                
                # 保存结果
                if save_results:
                    result = {
                        'private_key_hex': private_key_hex,
                        'private_key_int': private_key_int,
                        'address': address,
                        'worker_id': worker_id,
                        'timestamp': time.time()
                    }
                    queue.put(result)
                
                break
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"进程 {worker_id} 错误: {e}")
            continue
    
    print(f"工作进程 {worker_id} 结束, 共检查 {keys_checked:,} 个密钥")

def save_worker(queue, stop_event):
    """保存结果的工作线程"""
    results_dir = "bitcoin_search_results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(results_dir, f"found_key_{timestamp}.txt")
    
    while not stop_event.is_set() or not queue.empty():
        try:
            result = queue.get(timeout=1)
            if result:
                with open(filename, 'w') as f:
                    f.write("比特币私钥碰撞结果\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"发现时间: {time.ctime(result['timestamp'])}\n")
                    f.write(f"工作进程: {result['worker_id']}\n")
                    f.write(f"私钥 (十六进制): {result['private_key_hex']}\n")
                    f.write(f"私钥 (十进制): {result['private_key_int']}\n")
                    f.write(f"地址: {result['address']}\n")
                print(f"结果已保存到: {filename}")
        except:
            pass

def main():
    """主函数"""
    print("比特币地址碰撞搜索")
    print("=" * 50)
    print(f"目标地址: {TARGET_ADDRESS}")
    print(f"搜索范围: 2^{START_EXPONENT} 到 2^{END_EXPONENT}")
    print(f"CPU 核心数: {mp.cpu_count()}")
    
    # 询问是否保存结果
    save_choice = input("是否保存找到的私钥到文件? (y/n): ").lower().strip()
    save_results = save_choice in ['y', 'yes', '1']
    
    # 设置进程数
    num_processes = min(mp.cpu_count(), 16)  # 最多16个进程
    print(f"使用 {num_processes} 个进程进行搜索")
    
    # 创建共享变量
    found_flag = Value('b', False)
    counter = Value('i', 0)
    queue = Queue()
    
    # 创建密钥生成器
    key_generator = KeyGenerator(START_RANGE, END_RANGE)
    
    # 创建保存线程
    stop_event = threading.Event()
    if save_results:
        saver_thread = threading.Thread(target=save_worker, args=(queue, stop_event))
        saver_thread.daemon = True
        saver_thread.start()
    
    # 创建并启动工作进程
    processes = []
    try:
        for i in range(num_processes):
            p = Process(target=worker, args=(i, key_generator, found_flag, counter, save_results, queue))
            p.daemon = True
            p.start()
            processes.append(p)
        
        # 显示总体进度
        start_time = time.time()
        last_count = 0
        
        while not found_flag.value and any(p.is_alive() for p in processes):
            time.sleep(5)
            current_count = counter.value
            elapsed = time.time() - start_time
            rate = (current_count - last_count) / 5 if elapsed > 5 else current_count / elapsed
            
            print(f"\r总进度: {current_count:,} 密钥, 速率: {rate:,.0f} 密钥/秒, 运行时间: {elapsed:.0f}秒", end="")
            last_count = current_count
            
        print()
        
        # 等待所有进程结束
        for p in processes:
            p.join(timeout=1)
            
    except KeyboardInterrupt:
        print("\n正在停止所有进程...")
        found_flag.value = True
        for p in processes:
            p.terminate()
            p.join()
    
    finally:
        stop_event.set()
        if save_results:
            saver_thread.join(timeout=2)
    
    if found_flag.value:
        print("搜索成功完成！")
    else:
        print("搜索被中断或完成")

if __name__ == "__main__":
    # 设置随机种子
    random.seed(time.time())
    
    # 在Linux上设置启动方法
    if sys.platform.startswith('linux'):
        mp.set_start_method('spawn')
    
    main()
