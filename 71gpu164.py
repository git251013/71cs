#!/usr/bin/env python3
"""
比特币私钥扫描器 - GPU加速版本
扫描范围: 2^70 到 2^71
目标地址: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
"""

import os
import sys
import time
import hashlib
import multiprocessing as mp
from datetime import datetime

# 自动安装必要的库
def install_requirements():
    try:
        import base58
    except ImportError:
        print("安装base58库...")
        os.system("pip install base58")
        import base58
    
    try:
        import numpy as np
    except ImportError:
        print("安装numpy库...")
        os.system("pip install numpy")
        import numpy as np
        
    try:
        import cupy as cp
    except ImportError:
        print("安装cupy库...")
        os.system("pip install cupy-cuda11x")
        import cupy as cp
        
    return base58, np, cp

# 安装库并导入
base58, np, cp = install_requirements()

# 目标地址
TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

class BitcoinKeyScanner:
    def __init__(self):
        self.start_range = 2**70
        self.end_range = 2**71
        self.batch_size = 1000000  # 每批处理的私钥数量
        self.target_hash160 = self.address_to_hash160(TARGET_ADDRESS)
        
    def address_to_hash160(self, address):
        """将比特币地址转换回hash160"""
        decoded = base58.b58decode(address)
        return decoded[1:21]  # 跳过版本字节，取hash160部分
        
    def private_key_to_compressed_address(self, private_key_int):
        """将私钥整数转换为压缩地址"""
        # 使用cupy进行椭圆曲线计算
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        # 计算公钥点 = private_key * G
        priv_key = private_key_int % n
        if priv_key == 0:
            return None
            
        # 使用倍加算法计算椭圆曲线点乘
        result_x, result_y = self.ec_multiply(Gx, Gy, priv_key, a, b, p)
        
        if result_x is None:
            return None
            
        # 压缩公钥格式
        if result_y % 2 == 0:
            compressed_pubkey = b'\x02' + result_x.to_bytes(32, 'big')
        else:
            compressed_pubkey = b'\x03' + result_x.to_bytes(32, 'big')
            
        # SHA-256哈希
        sha256_result = hashlib.sha256(compressed_pubkey).digest()
        
        # RIPEMD-160哈希
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_result)
        hash160 = ripemd160.digest()
        
        # 添加比特币主网版本字节
        version_hash160 = b'\x00' + hash160
        
        # 计算校验和
        checksum = hashlib.sha256(hashlib.sha256(version_hash160).digest()).digest()[:4]
        
        # Base58编码
        address_bytes = version_hash160 + checksum
        bitcoin_address = base58.b58encode(address_bytes).decode('ascii')
        
        return bitcoin_address
        
    def ec_multiply(self, x, y, scalar, a, b, p):
        """椭圆曲线点乘计算"""
        # 使用倍加算法
        result_x = None
        result_y = None
        addend_x = x
        addend_y = y
        
        while scalar:
            if scalar & 1:
                if result_x is None:
                    result_x = addend_x
                    result_y = addend_y
                else:
                    result_x, result_y = self.ec_add(result_x, result_y, addend_x, addend_y, a, p)
            addend_x, addend_y = self.ec_double(addend_x, addend_y, a, p)
            scalar >>= 1
            
        return result_x, result_y
        
    def ec_double(self, x, y, a, p):
        """椭圆曲线点加倍"""
        if y == 0:
            return None, None
            
        s = (3 * x * x + a) * pow(2 * y, p - 2, p) % p
        x3 = (s * s - 2 * x) % p
        y3 = (s * (x - x3) - y) % p
        
        return x3, y3
        
    def ec_add(self, x1, y1, x2, y2, a, p):
        """椭圆曲线点相加"""
        if x1 == x2:
            if y1 == y2:
                return self.ec_double(x1, y1, a, p)
            else:
                return None, None
                
        s = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        
        return x3, y3
        
    def process_batch_gpu(self, start_key):
        """使用GPU处理一批私钥"""
        try:
            # 创建私钥范围
            keys_cpu = np.arange(start_key, start_key + self.batch_size, dtype=object)
            
            # 转换为cupy数组进行GPU计算
            keys_gpu = cp.asarray(keys_cpu)
            
            found_key = None
            processed = 0
            
            # 批量处理私钥
            for i in range(len(keys_gpu)):
                private_key_int = int(keys_gpu[i])
                address = self.private_key_to_compressed_address(private_key_int)
                
                if address == TARGET_ADDRESS:
                    found_key = private_key_int
                    break
                    
                processed += 1
                
                # 每处理10000个键输出一次统计信息
                if processed % 10000 == 0:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{current_time}] 处理进度: {start_key + processed}/{self.end_range} "
                          f"({(start_key + processed - self.start_range) / (self.end_range - self.start_range) * 100:.6f}%)")
            
            return found_key, processed
            
        except Exception as e:
            print(f"GPU处理错误: {e}")
            return None, 0
            
    def scan_range(self):
        """扫描指定范围的私钥"""
        print(f"开始扫描范围: {self.start_range} 到 {self.end_range}")
        print(f"目标地址: {TARGET_ADDRESS}")
        print(f"批次大小: {self.batch_size}")
        print("=" * 60)
        
        start_time = time.time()
        total_processed = 0
        current_key = self.start_range
        
        while current_key < self.end_range:
            batch_end = min(current_key + self.batch_size, self.end_range)
            actual_batch_size = batch_end - current_key
            
            print(f"处理批次: {current_key} 到 {batch_end}")
            
            found_key, processed = self.process_batch_gpu(current_key)
            
            if found_key:
                elapsed_time = time.time() - start_time
                print("\n" + "=" * 60)
                print("🎉 找到目标私钥! 🎉")
                print(f"私钥 (十进制): {found_key}")
                print(f"私钥 (十六进制): {hex(found_key)}")
                print(f"对应地址: {TARGET_ADDRESS}")
                print(f"总处理时间: {elapsed_time:.2f} 秒")
                print(f"总处理密钥数: {total_processed + processed}")
                print("=" * 60)
                
                # 保存结果到文件
                with open("found_private_key.txt", "w") as f:
                    f.write(f"私钥 (十进制): {found_key}\n")
                    f.write(f"私钥 (十六进制): {hex(found_key)}\n")
                    f.write(f"对应地址: {TARGET_ADDRESS}\n")
                    f.write(f"找到时间: {datetime.now()}\n")
                
                return found_key
                
            total_processed += processed
            current_key = batch_end
            
            # 显示统计信息
            elapsed_time = time.time() - start_time
            keys_per_second = total_processed / elapsed_time if elapsed_time > 0 else 0
            progress_percent = (current_key - self.start_range) / (self.end_range - self.start_range) * 100
            
            print(f"统计信息:")
            print(f"  已处理: {total_processed} 个密钥")
            print(f"  进度: {progress_percent:.6f}%")
            print(f"  速度: {keys_per_second:.2f} 密钥/秒")
            print(f"  运行时间: {elapsed_time:.2f} 秒")
            print("-" * 40)
        
        # 如果没有找到
        elapsed_time = time.time() - start_time
        print("\n" + "=" * 60)
        print("扫描完成，未找到目标私钥")
        print(f"总处理时间: {elapsed_time:.2f} 秒")
        print(f"总处理密钥数: {total_processed}")
        print(f"平均速度: {total_processed/elapsed_time:.2f} 密钥/秒")
        print("=" * 60)
        
        return None

def main():
    """主函数"""
    print("比特币私钥扫描器 - GPU加速版")
    print("正在初始化...")
    
    try:
        scanner = BitcoinKeyScanner()
        scanner.scan_range()
        
    except KeyboardInterrupt:
        print("\n用户中断扫描")
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
