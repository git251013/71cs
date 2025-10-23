import os
import hashlib
import base58
import ecdsa
import secrets
import json
import time
import multiprocessing
from typing import List, Tuple, Dict, Set
from multiprocessing import Process, Manager, Queue, Value, Lock

def generate_private_key_in_range(start: int, end: int) -> int:
    """在指定范围内生成随机私钥"""
    range_size = end - start
    return start + secrets.randbelow(range_size)

def generate_private_key_with_step(start: int, step: int, counter) -> int:
    """使用递增步长生成私钥"""
    with counter.get_lock():
        current = counter.value
        counter.value += step
    return start + current

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

def worker_process(process_id: int, 
                  target_addresses: Set[str],
                  ranges: List[Tuple[int, int, str]],
                  found_addresses: Set[str],
                  results: List[Dict],
                  total_attempts: Value,
                  found_counter: Value,
                  use_step_method: bool = False,
                  step_size: int = 1000,
                  max_attempts_per_range: int = 500000):
    """工作进程函数"""
    
    print(f"进程 {process_id} 启动")
    local_attempts = 0
    local_start_time = time.time()
    
    for range_idx, (start, end, range_desc) in enumerate(ranges, 1):
        if len(found_addresses) >= len(target_addresses):
            break
            
        print(f"进程 {process_id} 搜索区间 {range_idx}/{len(ranges)}: {range_desc}")
        
        attempts_in_range = 0
        
        if use_step_method:
            # 使用递增步长方法
            counter = Value('i', process_id)  # 每个进程从不同的起始点开始
            while (attempts_in_range < max_attempts_per_range and 
                   len(found_addresses) < len(target_addresses)):
                
                attempts_in_range += 1
                local_attempts += 1
                with total_attempts.get_lock():
                    total_attempts.value += 1
                
                # 使用递增步长生成私钥
                private_key_int = generate_private_key_with_step(start, step_size, counter)
                
                # 检查是否超出范围
                if private_key_int >= end:
                    break
                
                # 生成地址
                address = private_key_to_address(private_key_int)
                
                # 检查是否匹配目标地址
                if address in target_addresses and address not in found_addresses:
                    wif = private_key_to_wif(private_key_int)
                    
                    result = {
                        "address": address,
                        "private_key_wif": wif,
                        "private_key_hex": format(private_key_int, '064x'),
                        "private_key_decimal": str(private_key_int),
                        "range": range_desc,
                        "process_id": process_id,
                        "attempts_in_range": attempts_in_range,
                        "total_attempts": total_attempts.value,
                        "found_time": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    results.append(result)
                    found_addresses.add(address)
                    with found_counter.get_lock():
                        found_counter.value += 1
                    
                    print(f"🎯 进程 {process_id} 找到匹配地址!")
                    print(f"   地址: {address}")
                    print(f"   所在区间: {range_desc}")
                    print(f"   区间内尝试次数: {attempts_in_range}")
                    print(f"   总尝试次数: {total_attempts.value}")
                    print(f"   找到时间: {result['found_time']}")
                    print("-" * 40)
                    
                    # 如果找到所有目标地址，提前结束
                    if len(found_addresses) >= len(target_addresses):
                        break
        else:
            # 使用随机方法
            while (attempts_in_range < max_attempts_per_range and 
                   len(found_addresses) < len(target_addresses)):
                
                attempts_in_range += 1
                local_attempts += 1
                with total_attempts.get_lock():
                    total_attempts.value += 1
                
                # 生成私钥
                private_key_int = generate_private_key_in_range(start, end)
                
                # 生成地址
                address = private_key_to_address(private_key_int)
                
                # 检查是否匹配目标地址
                if address in target_addresses and address not in found_addresses:
                    wif = private_key_to_wif(private_key_int)
                    
                    result = {
                        "address": address,
                        "private_key_wif": wif,
                        "private_key_hex": format(private_key_int, '064x'),
                        "private_key_decimal": str(private_key_int),
                        "range": range_desc,
                        "process_id": process_id,
                        "attempts_in_range": attempts_in_range,
                        "total_attempts": total_attempts.value,
                        "found_time": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    results.append(result)
                    found_addresses.add(address)
                    with found_counter.get_lock():
                        found_counter.value += 1
                    
                    print(f"🎯 进程 {process_id} 找到匹配地址!")
                    print(f"   地址: {address}")
                    print(f"   所在区间: {range_desc}")
                    print(f"   区间内尝试次数: {attempts_in_range}")
                    print(f"   总尝试次数: {total_attempts.value}")
                    print(f"   找到时间: {result['found_time']}")
                    print("-" * 40)
                    
                    # 如果找到所有目标地址，提前结束
                    if len(found_addresses) >= len(target_addresses):
                        break
        
        # 显示进度
        if attempts_in_range > 0:
            elapsed_time = time.time() - local_start_time
            rate = local_attempts / elapsed_time if elapsed_time > 0 else 0
            print(f"进程 {process_id} 区间 {range_idx} 完成: 尝试 {attempts_in_range:,} 次, 速度: {rate:.1f} 次/秒")
    
    print(f"进程 {process_id} 完成, 总尝试次数: {local_attempts:,}")

def generate_and_search_multiprocess(num_processes: int = 20, use_step_method: bool = False, step_size: int = 1000):
    """多进程生成私钥并搜索目标地址"""
    target_addresses = {
        "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
        "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR", 
        "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
        "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
        "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF",
        "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"
    }
    
    # 使用Manager创建共享对象
    with Manager() as manager:
        shared_found_addresses = manager.set(target_addresses)  # 只读的
        shared_results = manager.list()
        shared_total_attempts = Value('i', 0)
        shared_found_counter = Value('i', 0)
        
        # 创建进程安全的已找到地址集合
        found_addresses_set = set()
        
        # 定义范围
        ranges = []
        for i in range(70, 77):
            start = 2 ** i
            end = 2 ** (i + 1)
            ranges.append((start, end, f"2^{i} to 2^{i+1}"))
        
        print("开始多进程搜索目标地址...")
        print("目标地址列表:")
        for i, addr in enumerate(target_addresses, 1):
            print(f"  {i}. {addr}")
        print(f"\n使用进程数: {num_processes}")
        print(f"搜索方法: {'递增步长' if use_step_method else '随机生成'}")
        if use_step_method:
            print(f"步长大小: {step_size}")
        print(f"搜索范围: {len(ranges)} 个区间")
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
                    ranges,
                    found_addresses_set,  # 注意：这个在进程间不会自动同步
                    shared_results,
                    shared_total_attempts,
                    shared_found_counter,
                    use_step_method,
                    step_size,
                    500000 // num_processes  # 每个进程的尝试次数
                )
            )
            processes.append(p)
            p.start()
        
        # 等待所有进程完成
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
        
        if len(final_results) > 0:
            print(f"\n找到的地址详情:")
            for i, result in enumerate(final_results, 1):
                print(f"{i}. 地址: {result['address']}")
                print(f"   私钥(WIF): {result['private_key_wif']}")
                print(f"   进程ID: {result['process_id']}")
                print(f"   所在区间: {result['range']}")
                print()
            
            # 保存结果
            save_results(final_results)
        else:
            print("未找到任何目标地址")
        
        return final_results

def main():
    """主函数"""
    print("比特币地址多进程搜索工具")
    print("=" * 50)
    print("此工具使用多进程并行搜索，大幅提高搜索效率")
    print("=" * 50)
    
    # 配置参数
    num_processes = 20  # 进程数量
    use_step_method = True  # 是否使用递增步长方法
    step_size = 1000  # 步长大小
    
    try:
        results = generate_and_search_multiprocess(
            num_processes=num_processes,
            use_step_method=use_step_method,
            step_size=step_size
        )
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # 设置多进程启动方法
    multiprocessing.set_start_method('spawn', force=True)
    main()
