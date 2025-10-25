import os
import hashlib
import ecdsa
import base58
import time
import multiprocessing
from multiprocessing import Process, Manager, Value, Event

# 目标地址列表
TARGET_ADDRESSES = [
    "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR", 
    "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
    "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
    "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF",
    "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE",
    "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb",
    "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8",
    "15qsCm78whspNQFydGJQk5rexzxTQopnHZ",
    "13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC",
    "14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2",
    "1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D",
    "1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK",
    "1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq",
    "16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf",
    "19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt",
    "1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74",
    "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5",
    "17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad",
    "1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL",
    "15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b",
    "18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8",
    "1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX",
    "1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL",
    "1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n"
]

def generate_private_key_in_range(start, end):
    """在指定范围内生成随机私钥"""
    # 确保范围有效
    if start >= end:
        raise ValueError("起始值必须小于结束值")
    
    # 比特币私钥的最大值 (secp256k1曲线的阶 - 1)
    max_private_key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    # 确保范围不超过比特币允许的最大值
    end = min(end, max_private_key)
    if start >= end:
        start = end - 1
    
    # 生成范围内的随机私钥
    range_size = end - start
    random_bytes = os.urandom(32)
    random_int = int.from_bytes(random_bytes, 'big')
    private_key_int = start + (random_int % range_size)
    
    # 确保私钥在有效范围内
    private_key_int = max(1, min(private_key_int, max_private_key))
    
    return format(private_key_int, '064x')

def private_key_to_compressed_public_key(private_key_hex):
    """从私钥生成压缩公钥"""
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # 使用ecdsa生成公钥
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    
    # 获取公钥坐标
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    
    # 生成压缩公钥 (根据y坐标的奇偶性选择前缀)
    if y % 2 == 0:
        compressed_public_key = b'\x02' + x.to_bytes(32, 'big')
    else:
        compressed_public_key = b'\x03' + x.to_bytes(32, 'big')
    
    return compressed_public_key

def public_key_to_address(public_key):
    """从公钥生成比特币地址"""
    # SHA-256哈希
    sha256_hash = hashlib.sha256(public_key).digest()
    
    # RIPEMD-160哈希
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    ripemd160_hash = ripemd160.digest()
    
    # 添加版本字节（0x00为主网）
    versioned_payload = b'\x00' + ripemd160_hash
    
    # 计算校验和
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    
    # 组合并Base58编码
    binary_address = versioned_payload + checksum
    bitcoin_address = base58.b58encode(binary_address)
    
    return bitcoin_address.decode('utf-8')

def generate_addresses():
    """生成160个地址，每个在指定的指数范围内"""
    found_addresses = {}  # 存储找到的目标地址和对应的私钥
    total_generated = 0
    start_time = time.time()
    
    print("生成160个在指数范围内的地址：")
    print(f"目标地址数量: {len(TARGET_ADDRESSES)}")
    print("-" * 100)
    
    for i in range(160):
        # 计算当前范围
        start_range = 2 ** i
        end_range = 2 ** (i + 1)
        
        # 生成当前范围内的私钥
        private_key_hex = generate_private_key_in_range(start_range, end_range)
        
        # 生成压缩公钥和地址
        compressed_public_key = private_key_to_compressed_public_key(private_key_hex)
        address = public_key_to_address(compressed_public_key)
        
        total_generated += 1
        
        # 检查是否匹配任何目标地址
        if address in TARGET_ADDRESSES:
            found_addresses[address] = private_key_hex
            marker = f"🎯 找到目标地址! ({len(found_addresses)}/{len(TARGET_ADDRESSES)})"
        else:
            marker = ""
        
        print(f"范围 2^{i}-2^{i+1}: 私钥: {private_key_hex} | 地址: {address} {marker}")
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print(f"\n统计信息:")
    print(f"生成地址总数: {total_generated}")
    print(f"耗时: {elapsed_time:.2f} 秒")
    print(f"平均每个地址生成时间: {elapsed_time/total_generated:.4f} 秒")
    
    if found_addresses:
        print(f"\n🎉 成功找到 {len(found_addresses)} 个目标地址:")
        for addr, priv_key in found_addresses.items():
            print(f"地址: {addr}")
            print(f"私钥: {priv_key}")
            print("-" * 80)
    else:
        print(f"\n⚠️  在{total_generated}个地址中未找到任何目标地址")
        print("提示：在随机生成中匹配特定地址的概率极低。")

def worker_process(worker_id, found_addresses, total_generated, stop_event, batch_size=1000):
    """工作进程函数，用于多进程搜索"""
    local_generated = 0
    
    while not stop_event.is_set():
        for _ in range(batch_size):
            # 生成随机私钥
            private_key_hex = os.urandom(32).hex()
            
            # 生成压缩公钥和地址
            compressed_public_key = private_key_to_compressed_public_key(private_key_hex)
            address = public_key_to_address(compressed_public_key)
            
            local_generated += 1
            
            # 检查是否匹配任何目标地址
            if address in TARGET_ADDRESSES and address not in found_addresses:
                # 使用Manager字典的原子操作来避免竞争条件
                if address not in found_addresses:  # 双重检查
                    found_addresses[address] = private_key_hex
                    print(f"\n🎉 进程 {worker_id} 找到新目标地址 ({len(found_addresses)}/{len(TARGET_ADDRESSES)})!")
                    print(f"私钥: {private_key_hex}")
                    print(f"地址: {address}")
                    print("-" * 80)
                    
                    # 如果找到所有目标地址，设置停止事件
                    if len(found_addresses) >= len(TARGET_ADDRESSES):
                        stop_event.set()
                        break
        
        # 更新总生成计数 - 使用原子操作
        total_generated.value += local_generated
        local_generated = 0
        
        # 短暂休眠以避免过度占用CPU
        time.sleep(0.01)

def multi_process_search(num_processes=None):
    """多进程搜索目标地址"""
    if num_processes is None:
        num_processes = multiprocessing.cpu_count()
    
    print(f"启动 {num_processes} 个进程进行搜索")
    print(f"目标地址数量: {len(TARGET_ADDRESSES)}")
    print("按Ctrl+C停止搜索")
    print("-" * 100)
    
    # 使用Manager创建共享对象
    with Manager() as manager:
        # 共享字典，用于存储找到的地址
        found_addresses = manager.dict()
        
        # 共享值，用于统计总生成数量
        total_generated = manager.Value('i', 0)
        
        # 事件，用于通知所有进程停止
        stop_event = manager.Event()
        
        # 启动工作进程
        processes = []
        start_time = time.time()
        
        try:
            for i in range(num_processes):
                p = Process(target=worker_process, 
                           args=(i, found_addresses, total_generated, stop_event))
                p.daemon = True
                p.start()
                processes.append(p)
            
            # 主进程监控进度
            last_count = 0
            last_time = start_time
            
            while not stop_event.is_set() and len(found_addresses) < len(TARGET_ADDRESSES):
                time.sleep(1)  # 每秒更新一次进度
                
                current_count = total_generated.value
                current_time = time.time()
                
                # 计算速度
                time_diff = current_time - last_time
                count_diff = current_count - last_count
                speed = count_diff / time_diff if time_diff > 0 else 0
                
                # 显示进度
                progress = f"已生成: {current_count} | 找到: {len(found_addresses)}/{len(TARGET_ADDRESSES)} | 速度: {speed:.2f} 地址/秒"
                print(progress, end='\r')
                
                last_count = current_count
                last_time = current_time
            
            # 设置停止事件，确保所有进程都停止
            stop_event.set()
            
            # 等待所有进程结束
            for p in processes:
                p.join(timeout=2)
                if p.is_alive():
                    p.terminate()
                    
        except KeyboardInterrupt:
            print(f"\n\n用户中断搜索")
            stop_event.set()
            
            # 等待进程结束
            for p in processes:
                p.join(timeout=2)
                if p.is_alive():
                    p.terminate()
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        print(f"\n统计信息:")
        print(f"生成地址总数: {total_generated.value}")
        print(f"总耗时: {elapsed_time:.2f} 秒")
        print(f"平均速度: {total_generated.value/elapsed_time:.2f} 地址/秒")
        print(f"使用进程数: {num_processes}")
        
        # 将Manager字典转换为普通字典以便显示
        found_dict = dict(found_addresses)
        if found_dict:
            print(f"\n🎉 成功找到 {len(found_dict)} 个目标地址:")
            for addr, priv_key in found_dict.items():
                print(f"地址: {addr}")
                print(f"私钥: {priv_key}")
                print("-" * 80)
        else:
            print(f"\n⚠️  未找到任何目标地址")

def single_process_search():
    """单进程持续搜索"""
    found_addresses = {}
    total_generated = 0
    start_time = time.time()
    batch_size = 1000
    
    print(f"单进程搜索目标地址: {len(TARGET_ADDRESSES)} 个")
    print("按Ctrl+C停止搜索")
    print("-" * 100)
    
    try:
        while len(found_addresses) < len(TARGET_ADDRESSES):
            batch_start = time.time()
            
            for _ in range(batch_size):
                # 生成随机私钥
                private_key_hex = os.urandom(32).hex()
                
                # 生成压缩公钥和地址
                compressed_public_key = private_key_to_compressed_public_key(private_key_hex)
                address = public_key_to_address(compressed_public_key)
                
                total_generated += 1
                
                # 检查是否匹配任何目标地址
                if address in TARGET_ADDRESSES and address not in found_addresses:
                    found_addresses[address] = private_key_hex
                    print(f"\n🎉 找到新目标地址 ({len(found_addresses)}/{len(TARGET_ADDRESSES)})!")
                    print(f"私钥: {private_key_hex}")
                    print(f"地址: {address}")
                    print("-" * 80)
            
            batch_time = time.time() - batch_start
            speed = batch_size / batch_time if batch_time > 0 else 0
            
            # 显示进度
            progress = f"已生成: {total_generated} | 找到: {len(found_addresses)}/{len(TARGET_ADDRESSES)} | 速度: {speed:.2f} 地址/秒"
            print(progress, end='\r')
            
    except KeyboardInterrupt:
        print(f"\n\n用户中断搜索")
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print(f"\n统计信息:")
    print(f"生成地址总数: {total_generated}")
    print(f"总耗时: {elapsed_time:.2f} 秒")
    print(f"平均速度: {total_generated/elapsed_time:.2f} 地址/秒")
    
    if found_addresses:
        print(f"\n🎉 成功找到 {len(found_addresses)} 个目标地址:")
        for addr, priv_key in found_addresses.items():
            print(f"地址: {addr}")
            print(f"私钥: {priv_key}")
            print("-" * 80)
    else:
        print(f"\n⚠️  未找到任何目标地址")

def display_target_addresses():
    """显示所有目标地址"""
    print("目标地址列表:")
    for i, addr in enumerate(TARGET_ADDRESSES, 1):
        print(f"{i:2d}. {addr}")

if __name__ == "__main__":
    # 在Windows上，多进程需要这个保护
    multiprocessing.freeze_support()
    
    print("比特币地址生成器")
    print("=" * 50)
    display_target_addresses()
    print("\n选择模式:")
    print("1. 生成160个在指数范围内的地址")
    print("2. 单进程持续搜索")
    print("3. 多进程持续搜索")
    
    choice = input("\n请输入选择 (1, 2 或 3): ").strip()
    
    if choice == "1":
        generate_addresses()
    elif choice == "2":
        single_process_search()
    elif choice == "3":
        # 多进程搜索
        try:
            cpu_count = multiprocessing.cpu_count()
            default_processes = min(cpu_count, 8)  # 限制默认进程数
            user_input = input(f"请输入要使用的进程数 (建议 1-{cpu_count}, 默认{default_processes}): ").strip()
            if user_input:
                num_processes = int(user_input)
                num_processes = max(1, min(num_processes, cpu_count * 2))  # 限制最大进程数
            else:
                num_processes = default_processes
            multi_process_search(num_processes)
        except ValueError:
            print("输入无效，使用默认进程数")
            multi_process_search()
    else:
        print("无效选择，默认使用模式1")
        generate_addresses()
