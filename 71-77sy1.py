import os
import hashlib
import base58
import ecdsa
import secrets
import json
import time
import multiprocessing
import subprocess
import sys
import csv
from typing import List, Tuple, Dict, Set
from multiprocessing import Process, Manager, Value, Lock

# 自动安装必要的库
def install_required_packages():
    """自动安装必要的依赖库"""
    required_packages = ['base58', 'ecdsa']
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} 已安装")
        except ImportError:
            print(f"正在安装 {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✓ {package} 安装成功")
            except subprocess.CalledProcessError:
                print(f"✗ {package} 安装失败，请手动安装: pip install {package}")
                sys.exit(1)

# 安装依赖
install_required_packages()

def generate_private_key_in_range(start: int, end: int) -> int:
    """在指定范围内生成随机私钥"""
    range_size = end - start
    return start + secrets.randbelow(range_size)

def generate_private_key_with_step(start: int, step: int, counter, process_id: int) -> int:
    """使用递增步长生成私钥"""
    with counter.get_lock():
        current = counter.value
        counter.value += step
    return start + current + (process_id * step)

def private_key_to_wif(private_key: int, compressed: bool = True) -> str:
    """将私钥整数转换为WIF格式"""
    priv_key_hex = format(private_key, '064x')
    priv_key_bytes = bytes.fromhex(priv_key_hex)
    
    extended_key = b'\x80' + priv_key_bytes
    if compressed:
        extended_key += b'\x01'
    
    first_hash = hashlib.sha256(extended_key).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    final_key = extended_key + second_hash[:4]
    
    return base58.b58encode(final_key).decode('ascii')

def private_key_to_address(private_key: int, compressed: bool = True) -> str:
    """从私钥生成比特币地址"""
    priv_key_hex = format(private_key, '064x')
    
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key_hex), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    
    if compressed:
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        if y & 1:
            public_key = bytes.fromhex('03' + format(x, '064x'))
        else:
            public_key = bytes.fromhex('02' + format(x, '064x'))
    else:
        public_key = b'\x04' + vk.to_string()
    
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    ripemd160_hash = ripemd160.digest()
    
    network_byte = b'\x00'
    extended_hash = network_byte + ripemd160_hash
    
    first_checksum = hashlib.sha256(extended_hash).digest()
    second_checksum = hashlib.sha256(first_checksum).digest()
    checksum = second_checksum[:4]
    
    final_bytes = extended_hash + checksum
    return base58.b58encode(final_bytes).decode('ascii')

def save_results(results: List[Dict], filename: str = "found_addresses.json"):
    """保存匹配结果到JSON文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"结果已保存到: {filename}")

def save_all_keys_to_csv(keys_data: List[Dict], filename: str = "all_generated_keys.csv"):
    """保存所有生成的私钥和地址到CSV文件"""
    if not keys_data:
        return
        
    fieldnames = ["process_id", "private_key_decimal", "private_key_hex", "private_key_wif", "address", "timestamp"]
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for data in keys_data:
            writer.writerow(data)
    
    print(f"所有生成的密钥已保存到: {filename} (共 {len(keys_data)} 条记录)")

def worker_process(process_id: int, 
                  target_addresses_set: set,
                  start_range: int,
                  end_range: int,
                  shared_results: list,
                  shared_all_keys: list,
                  total_attempts: Value,
                  found_counter: Value,
                  found_lock: Lock,
                  use_step_method: bool = True,
                  step_size: int = 1000,
                  max_attempts: int = 500000,
                  save_all_keys: bool = True):
    """工作进程函数"""
    
    print(f"进程 {process_id} 启动，搜索范围: {start_range:,} 到 {end_range:,}")
    local_attempts = 0
    local_start_time = time.time()
    local_found = 0
    local_keys = []  # 本地保存生成的密钥
    
    # 使用共享计数器实现递增步长
    counter = Value('i', 0)
    
    while (local_attempts < max_attempts and 
           found_counter.value < len(target_addresses_set)):
        
        local_attempts += 1
        with total_attempts.get_lock():
            total_attempts.value += 1
        
        # 生成私钥
        if use_step_method:
            private_key_int = generate_private_key_with_step(start_range, step_size, counter, process_id)
            # 检查是否超出范围
            if private_key_int >= end_range:
                break
        else:
            private_key_int = generate_private_key_in_range(start_range, end_range)
        
        # 生成地址
        address = private_key_to_address(private_key_int)
        
        # 保存所有生成的密钥（如果启用）
        if save_all_keys:
            key_data = {
                "process_id": process_id,
                "private_key_decimal": str(private_key_int),
                "private_key_hex": format(private_key_int, '064x'),
                "private_key_wif": private_key_to_wif(private_key_int),
                "address": address,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            local_keys.append(key_data)
            
            # 每1000条记录批量保存到共享列表
            if len(local_keys) >= 1000:
                with found_lock:
                    shared_all_keys.extend(local_keys)
                local_keys = []
        
        # 检查是否匹配目标地址
        if address in target_addresses_set:
            with found_lock:
                # 再次检查防止重复添加
                already_found = any(r['address'] == address for r in shared_results)
                if not already_found:
                    wif = private_key_to_wif(private_key_int)
                    
                    result = {
                        "address": address,
                        "private_key_wif": wif,
                        "private_key_hex": format(private_key_int, '064x'),
                        "private_key_decimal": str(private_key_int),
                        "range": f"2^70 to 2^77 (合并区间)",
                        "process_id": process_id,
                        "attempts": local_attempts,
                        "total_attempts": total_attempts.value,
                        "found_time": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    shared_results.append(result)
                    local_found += 1
                    with found_counter.get_lock():
                        found_counter.value += 1
                    
                    print(f"🎯 进程 {process_id} 找到匹配地址!")
                    print(f"   地址: {address}")
                    print(f"   进程ID: {process_id}")
                    print(f"   尝试次数: {local_attempts}")
                    print(f"   总尝试次数: {total_attempts.value}")
                    print(f"   找到时间: {result['found_time']}")
                    print("-" * 50)
                    
                    # 立即保存结果
                    save_results(list(shared_results))
            
            # 如果找到所有目标地址，提前结束
            if found_counter.value >= len(target_addresses_set):
                break
        
        # 显示进度
        if local_attempts % 10000 == 0:
            elapsed_time = time.time() - local_start_time
            rate = local_attempts / elapsed_time if elapsed_time > 0 else 0
            print(f"进程 {process_id}: 已尝试 {local_attempts:,} 次, 速度: {rate:.1f} 次/秒, 找到 {local_found} 个地址")
    
    # 保存剩余本地密钥
    if save_all_keys and local_keys:
        with found_lock:
            shared_all_keys.extend(local_keys)
    
    # 进程完成统计
    elapsed_time = time.time() - local_start_time
    print(f"进程 {process_id} 完成: 尝试 {local_attempts:,} 次, 找到 {local_found} 个地址, 平均速度: {local_attempts/elapsed_time:.1f} 次/秒")

def generate_and_search_multiprocess(num_processes: int = 20, use_step_method: bool = True, step_size: int = 1000, save_all_keys: bool = True):
    """多进程生成私钥并搜索目标地址"""
    target_addresses = {
        "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
        "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR", 
        "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
        "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
        "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF",
        "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"
    }
    
    # 设置多进程启动方法 
    try:
        multiprocessing.set_start_method('fork', force=True)
    except RuntimeError:
        pass
    
    # 使用Manager创建共享对象 
    with Manager() as manager:
        # 创建共享列表和值
        shared_results = manager.list()
        shared_all_keys = manager.list()
        shared_total_attempts = Value('i', 0)
        shared_found_counter = Value('i', 0)
        shared_lock = manager.Lock()
        
        # 合并区间为 2^70 到 2^77
        start_range = 2 ** 70
        end_range = 2 ** 77
        range_desc = f"2^70 to 2^77 (合并区间)"
        
        print("开始多进程搜索目标地址...")
        print("目标地址列表:")
        for i, addr in enumerate(target_addresses, 1):
            print(f"  {i}. {addr}")
        print(f"\n使用进程数: {num_processes}")
        print(f"搜索方法: {'递增步长' if use_step_method else '随机生成'}")
        if use_step_method:
            print(f"步长大小: {step_size}")
        print(f"搜索范围: {range_desc}")
        print(f"范围大小: {end_range - start_range:,}")
        print(f"保存所有密钥: {'是' if save_all_keys else '否'}")
        print("=" * 60)
        
        start_time = time.time()
        
        # 创建并启动进程
        processes = []
        for i in range(num_processes):
            p = Process(
                target=worker_process,
                args=(
                    i + 1,
                    target_addresses,
                    start_range,
                    end_range,
                    shared_results,
                    shared_all_keys,
                    shared_total_attempts,
                    shared_found_counter,
                    shared_lock,
                    use_step_method,
                    step_size,
                    500000 // num_processes,  # 每个进程的最大尝试次数
                    save_all_keys
                )
            )
            processes.append(p)
            p.start()
        
        # 等待所有进程完成
        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            print("\n接收到中断信号，正在停止所有进程...")
            for p in processes:
                p.terminate()
            for p in processes:
                p.join()
        
        # 最终统计
        end_time = time.time()
        total_time = end_time - start_time
        
        print("\n" + "=" * 60)
        print("所有进程搜索完成!")
        print(f"总运行时间: {total_time:.2f} 秒")
        print(f"总尝试次数: {shared_total_attempts.value:,}")
        print(f"平均速度: {shared_total_attempts.value / total_time:,.1f} 次/秒")
        print(f"找到地址数量: {shared_found_counter.value}/{len(target_addresses)}")
        
        # 转换共享结果为普通列表
        final_results = list(shared_results)
        all_keys_data = list(shared_all_keys)
        
        if len(final_results) > 0:
            print(f"\n找到的地址详情:")
            for i, result in enumerate(final_results, 1):
                print(f"{i}. 地址: {result['address']}")
                print(f"   私钥(WIF): {result['private_key_wif']}")
                print(f"   进程ID: {result['process_id']}")
                print(f"   所在区间: {result['range']}")
                print()
            
            # 保存最终结果
            save_results(final_results)
        else:
            print("未找到任何目标地址")
        
        # 保存所有生成的密钥
        if save_all_keys and all_keys_data:
            save_all_keys_to_csv(all_keys_data)
        
        return final_results, all_keys_data

def main():
    """主函数"""
    print("比特币地址多进程搜索工具 - 腾讯云服务器优化版")
    print("=" * 50)
    print("此工具使用多进程并行搜索，大幅提高搜索效率")
    print("自动安装依赖库，合并搜索区间，优化性能")
    print("=" * 50)
    
    # 配置参数
    num_processes = 20  # 进程数量
    use_step_method = True  # 使用递增步长方法
    step_size = 1000  # 步长大小
    save_all_keys = True  # 是否保存所有生成的密钥
    
    try:
        results, all_keys = generate_and_search_multiprocess(
            num_processes=num_processes,
            use_step_method=use_step_method,
            step_size=step_size,
            save_all_keys=save_all_keys
        )
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        # 如果已经有结果，保存当前进度
        if 'results' in locals() and results:
            save_results(list(results), "interrupted_results.json")
        if 'all_keys' in locals() and all_keys:
            save_all_keys_to_csv(list(all_keys), "interrupted_all_keys.csv")
    except Exception as e:
        print(f"发生错误: {e}")
        import traceback
        traceback.print_exc()
        if 'results' in locals() and results:
            save_results(list(results), "error_results.json")
        if 'all_keys' in locals() and all_keys:
            save_all_keys_to_csv(list(all_keys), "error_all_keys.csv")

if __name__ == "__main__":
    main()
