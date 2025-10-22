import os
import hashlib
import base58
import ecdsa
import secrets
import json
import time
from typing import List, Tuple, Dict

def generate_private_key_in_range(start: int, end: int) -> int:
    """在指定范围内生成随机私钥"""
    range_size = end - start
    return start + secrets.randbelow(range_size)

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

def generate_and_search():
    """生成私钥并搜索目标地址"""
    target_addresses = {
        "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
        "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR", 
        "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
        "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
        "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF",
        "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"
    }
    
    results = []
    found_addresses = set()
    used_private_keys = set()
    
    # 定义范围
    ranges = []
    for i in range(70, 77):
        start = 2 ** i
        end = 2 ** (i + 1)
        ranges.append((start, end, f"2^{i} to 2^{i+1}"))
    
    print("开始搜索目标地址...")
    print("目标地址列表:")
    for i, addr in enumerate(target_addresses, 1):
        print(f"  {i}. {addr}")
    print(f"\n搜索范围: {len(ranges)} 个区间")
    print("=" * 60)
    
    start_time = time.time()
    total_attempts = 0
    
    # 为每个范围生成私钥
    for range_idx, (start, end, range_desc) in enumerate(ranges, 1):
        print(f"\n搜索区间 {range_idx}/{len(ranges)}: {range_desc}")
        print(f"范围大小: {end - start:,}")
        
        attempts_in_range = 0
        max_attempts_per_range = 500000  # 每个范围的最大尝试次数
        
        while (attempts_in_range < max_attempts_per_range and 
               len(found_addresses) < len(target_addresses)):
            
            attempts_in_range += 1
            total_attempts += 1
            
            # 生成私钥
            private_key_int = generate_private_key_in_range(start, end)
            
            # 检查是否重复
            if private_key_int in used_private_keys:
                continue
                
            used_private_keys.add(private_key_int)
            
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
                    "attempts_in_range": attempts_in_range,
                    "total_attempts": total_attempts,
                    "found_time": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                results.append(result)
                found_addresses.add(address)
                
                print(f"🎯 找到匹配地址!")
                print(f"   地址: {address}")
                print(f"   所在区间: {range_desc}")
                print(f"   区间内尝试次数: {attempts_in_range}")
                print(f"   总尝试次数: {total_attempts}")
                print(f"   找到时间: {result['found_time']}")
                print("-" * 40)
                
                # 立即保存结果
                save_results(results)
                
                # 如果找到所有目标地址，提前结束
                if len(found_addresses) == len(target_addresses):
                    break
            
            # 显示进度
            if attempts_in_range % 10000 == 0:
                elapsed_time = time.time() - start_time
                rate = attempts_in_range / elapsed_time if elapsed_time > 0 else 0
                print(f"  已尝试 {attempts_in_range:,} 次, 速度: {rate:.1f} 次/秒")
        
        # 范围搜索完成统计
        elapsed_time = time.time() - start_time
        print(f"区间 {range_idx} 完成: 尝试 {attempts_in_range:,} 次, 找到 {len([r for r in results if r['range'] == range_desc])} 个地址")
    
    # 最终统计
    end_time = time.time()
    total_time = end_time - start_time
    
    print("\n" + "=" * 60)
    print("搜索完成!")
    print(f"总运行时间: {total_time:.2f} 秒")
    print(f"总尝试次数: {total_attempts:,}")
    print(f"找到地址数量: {len(results)}/{len(target_addresses)}")
    
    if len(results) > 0:
        print(f"\n找到的地址详情:")
        for i, result in enumerate(results, 1):
            print(f"{i}. 地址: {result['address']}")
            print(f"   私钥(WIF): {result['private_key_wif']}")
            print(f"   所在区间: {result['range']}")
            print()
    else:
        print("未找到任何目标地址")
    
    return results

def main():
    """主函数"""
    print("比特币地址搜索工具")
    print("=" * 50)
    print("此工具主要用于演示地址生成和搜索流程")
    print("=" * 50)
    
    try:
        results = generate_and_search()
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        # 如果已经有结果，保存当前进度
        if 'results' in locals() and results:
            save_results(results, "partial_results.json")
    except Exception as e:
        print(f"发生错误: {e}")
        if 'results' in locals() and results:
            save_results(results, "error_results.json")

if __name__ == "__main__":
    main()
