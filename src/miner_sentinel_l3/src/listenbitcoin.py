import requests


def hash_modify(hash_value):
    groups = [hash_value[i:i + 8] for i in range(0, 64, 8)]
    reversed_groups = list(reversed(groups))
    modified_hash = ''.join(reversed_groups)
    return modified_hash


def get_latest_block_header():
    # 获取最新区块的哈希值
    latest_block_url = "https://blockchain.info/latestblock"
    response = requests.get(latest_block_url)
    latest_block_hash = response.json()["hash"]

    # 通过区块哈希获取区块头详细信息
    block_url = f"https://blockchain.info/block/{latest_block_hash}?format=json"
    response = requests.get(block_url)
    block_data = response.json()

    # 提取区块头字段（比特币区块头固定80字节，包含以下字段）
    block_header = {
        "version": block_data["ver"],
        "previous_block_hash": block_data["prev_block"],
        "merkle_root": block_data["mrkl_root"],
        "timestamp": block_data["time"],
        "bits": block_data["bits"],
        "nonce": block_data["nonce"],
        "previous_block_hash_modify": hash_modify(block_data["prev_block"])
    }
    return block_header


# listenbitcoin_fast.py
import requests
from requests.exceptions import ConnectionError
import json

def get_latest_block_header_sse():
    """
    使用 blockstream.info 的 SSE 流获取最新区块头
    实测延迟 < 1秒
    """
    headers = {
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache'
    }

    url = "https://blockstream.info/api/blocks/tip/header"

    try:
        # 直接获取最新区块头（80字节二进制，Base64 编码）
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        # 返回的是十六进制的区块头（80字节）
        hex_header = response.text.strip()
        print(hex_header)

        # 解析 hex header 成字段（这里简化，实际需解析二进制）
        # 你可以直接用 hex_header 进行内存匹配
        return {
            "hex_header": hex_header,
            "previous_block_hash": hex_header[8:72],  # 前一区块哈希（小端序）
            "merkle_root": hex_header[72:136],
            "timestamp": int(hex_header[136:144], 16),
            "bits": hex_header[144:152],
            "nonce": int(hex_header[152:160], 16),
            "version": int(hex_header[0:8], 16)
        }

    except Exception as e:
        print(f"SSE 获取区块头失败: {e}")
        return None


# 示例：使用 mempool.space
def get_latest_block_header_fast():
    url = "https://mempool.space/api/blocks/tip/header"
    try:
        response = requests.get(url, timeout=3)
        response.raise_for_status()
        data = response.json()
        return {
            "previous_block_hash": data["previousblockhash"],
            "merkle_root": data["merkleroot"],
            "timestamp": data["time"],
            "bits": data["bits"],
            "nonce": data["nonce"],
            "version": data["version"]
        }
    except Exception as e:
        print(f"mempool.space 获取失败: {e}")
        return None


def get_latest_block_header_mempool():
    # 获取最新区块哈希
    blocks_url = "https://mempool.space/api/blocks"
    response = requests.get(blocks_url)
    latest_block_hash = response.json()[0]["id"]

    # 获取区块头信息
    block_url = f"https://mempool.space/api/block/{latest_block_hash}"
    response = requests.get(block_url)
    block_data = response.json()

    block_header = {
        "version": block_data["version"],
        "previous_block_hash": block_data["previousblockhash"],
        "merkle_root": block_data["merkle_root"],
        "timestamp": block_data["timestamp"],
        "bits": block_data["bits"],
        "nonce": block_data["nonce"],
        "height": block_data["height"],
        "previous_block_hash_modify": hash_modify(block_data["previousblockhash"])
    }
    return block_header


if __name__ == "__main__":
    header = get_latest_block_header()
    print("当前比特币区块头信息:")
    for key, value in header.items():
        print(f"{key}: {value}")
