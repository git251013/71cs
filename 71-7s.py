import hashlib
import base58
import ecdsa
from ecdsa.curves import SECP256k1

def private_key_to_wif(private_key_hex, compressed=True):
    """将16进制私钥转换为WIF格式"""
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # 添加主网版本字节 (0x80)
    extended_key = b'\x80' + private_key_bytes
    
    if compressed:
        extended_key += b'\x01'
    
    # 双重SHA256哈希
    first_hash = hashlib.sha256(extended_key).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    
    # 添加校验和 (前4字节)
    checksum = second_hash[:4]
    final_key = extended_key + checksum
    
    # Base58编码
    wif = base58.b58encode(final_key)
    return wif.decode('utf-8')

def private_key_to_address(private_key_hex, compressed=True):
    """从私钥生成比特币地址"""
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # 生成公钥
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    
    if compressed:
        # 压缩公钥
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        if y % 2 == 0:
            public_key = b'\x02' + x.to_bytes(32, 'big')
        else:
            public_key = b'\x03' + x.to_bytes(32, 'big')
    else:
        # 非压缩公钥
        public_key = b'\x04' + vk.pubkey.point.x().to_bytes(32, 'big') + vk.pubkey.point.y().to_bytes(32, 'big')
    
    # SHA256哈希
    sha256_hash = hashlib.sha256(public_key).digest()
    
    # RIPEMD160哈希
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    ripemd160_hash = ripemd160.digest()
    
    # 添加网络字节 (0x00 主网)
    network_byte = b'\x00' + ripemd160_hash
    
    # 双重SHA256哈希计算校验和
    first_checksum = hashlib.sha256(network_byte).digest()
    second_checksum = hashlib.sha256(first_checksum).digest()
    checksum = second_checksum[:4]
    
    # 最终地址字节
    address_bytes = network_byte + checksum
    
    # Base58编码
    address = base58.b58encode(address_bytes)
    return address.decode('utf-8')

def generate_private_keys(start_value, count, target_address=None):
    """从起始值生成指定数量的私钥，可选筛选目标地址"""
    print(f"从 {hex(start_value)} 开始生成 {count} 个私钥\n")
    
    if target_address:
        print(f"目标地址: {target_address}")
        print("正在搜索目标地址...")
        print("-" * 150)
    else:
        print("-" * 150)
        print(f"{'序号':<4} {'16进制私钥':<66} {'WIF格式(压缩)':<52}  {'比特币地址(压缩)'}")
        print("-" * 150)
    
    current_key = start_value
    found = False
    
    for i in range(count):
        # 将整数转换为64字符的16进制字符串
        private_key_hex = format(current_key, '064x')
        
        # 生成比特币地址
        address_compressed = private_key_to_address(private_key_hex, compressed=True)
        
        if target_address:
            # 筛选模式：只显示匹配的地址
            if address_compressed == target_address:
                found = True
                # 生成WIF格式
                wif_compressed = private_key_to_wif(private_key_hex, compressed=True)
                
                print("\n" + "🎯 找到目标地址! 🎯")
                print("=" * 150)
                print(f"目标地址: {target_address}")
                print(f"16进制私钥: {private_key_hex}")
                print(f"WIF格式(压缩): {wif_compressed}")
                print(f"比特币地址(压缩): {address_compressed}")
                print(f"私钥数值: {current_key}")
                print(f"搜索次数: {i + 1}")
                print("=" * 150)
                break
                
            # 显示进度
            if (i + 1) % 1000 == 0:
                print(f"已检查 {i + 1} 个私钥...")
        else:
            # 正常模式：显示所有私钥
            wif_compressed = private_key_to_wif(private_key_hex, compressed=True)
            print(f"{i+1:<4} {private_key_hex}  {wif_compressed}  {address_compressed}")
        
        current_key += 1
    
    if target_address and not found:
        print(f"\n在 {count} 个私钥中未找到目标地址: {target_address}")
        print(f"最后检查的私钥: {hex(current_key - 1)}")

def search_in_range(start_value, end_value, target_address):
    """在指定范围内搜索目标地址"""
    count = end_value - start_value + 1
    print(f"在范围 {hex(start_value)} 到 {hex(end_value)} 内搜索")
    print(f"搜索数量: {count:,} 个私钥")
    generate_private_keys(start_value, count, target_address)

# 主程序
if __name__ == "__main__":
    # 目标地址
    target_address = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
    
    print("比特币私钥搜索工具")
    print("=" * 80)
    
    # 选择模式
    print("请选择模式:")
    print("1. 生成连续的私钥列表")
    print("2. 搜索特定地址")
    
    choice = input("请输入选择 (1 或 2): ").strip()
    
    if choice == "1":
        # 原始模式：生成连续的私钥
        start_2_70 = 1199000000000000000000
        number_of_keys = 100
        
        print("\n比特币私钥生成器 (2^70 到 2^71 范围)")
        print("=" * 150)
        
        generate_private_keys(start_2_70, number_of_keys)
        
        print("\n" + "=" * 150)
        print(f"已成功生成 {number_of_keys} 个私钥")
        print(f"下一个起始私钥: {hex(start_2_70 + number_of_keys)}")
    
    elif choice == "2":
        # 搜索模式
        print(f"\n搜索目标地址: {target_address}")
        print("=" * 80)
        
        # 设置搜索范围
        print("\n设置搜索范围:")
        start_hex = input("请输入起始私钥(16进制, 例如: 1000000000000000000): ").strip()
        end_hex = input("请输入结束私钥(16进制, 例如: 2000000000000000000): ").strip()
        
        try:
            start_value = int(start_hex, 16)
            end_value = int(end_hex, 16)
            
            if start_value >= end_value:
                print("错误: 起始值必须小于结束值")
            else:
                search_in_range(start_value, end_value, target_address)
                
        except ValueError:
            print("错误: 请输入有效的16进制数")
    
    else:
        print("无效选择，请输入 1 或 2")
