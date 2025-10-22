import sys
  

  

  
def search_in_memory_maps(pid, search_string):
  
    found = False
  
    try:
  
        print(f"方法: 直接读取/proc/{pid}/mem")
  
        print("=" * 60)
  

  
        # 读取maps文件获取内存映射信息
  
        with open(f"/proc/{pid}/maps", "r") as maps_file:
  
            maps_content = maps_file.readlines()
  

  
        search_bytes = search_string.encode('utf-8')
  

  
        for line in maps_content:
  
            parts = line.split()
  
            if len(parts) < 5:
  
                continue
  

  
            addr_range = parts[0]
  
            perms = parts[1]
  
            pathname = parts[-1] if len(parts) > 5 else "[anonymous]"
  

  
            # 检查是否有读权限
  
            if 'r' in perms:
  
                try:
  
                    start_addr, end_addr = addr_range.split('-')
  
                    start_addr = int(start_addr, 16)
  
                    end_addr = int(end_addr, 16)
  
                    size = end_addr - start_addr
  
                    # 读取内存
  
                    with open(f"/proc/{pid}/mem", "rb") as mem_file:
  
                        mem_file.seek(start_addr)
  
                        # 限制读取大小
  
                        content = mem_file.read(min(size, 1024 * 1024))
  
                        if search_bytes in content:
  
                            offset = content.find(search_bytes)
  
                            actual_addr = start_addr + offset
  
                            print(f"\n 找到字符串:")
  
                            print(f"   内存区域: {addr_range}")
  
                            print(f"   权限: {perms}")
  
                            print(f"   路径: {pathname}")
  
                            print(f"   字符串地址: {hex(actual_addr)}")
  
                            print(f"   相对偏移: {hex(offset)}")
  
                            found = True
  

  
                except (PermissionError, OSError, ValueError):
  
                    continue
  

  
        if not found:
  
            print("未找到字符串")
  

  
    except FileNotFoundError:
  
        print(f"错误: 进程 {pid} 不存在或已退出")
  
    except PermissionError:
  
        print("错误: 权限不足，请使用sudo运行")
  
    finally:
  
        return found
  

  

  
if __name__ == "__main__":
  
    if len(sys.argv) != 3:
  
        print("用法: python search_memory.py <PID> <搜索字符串>")
  
        print("示例: python search_memory.py 1234 'abcdefghijk'")
  
        print("注意: 可能需要sudo权限")
  
        sys.exit(1)
  
    pid = int(sys.argv[1])
  
    search_string = sys.argv[2]
  
    print("搜索进程内存中的字符串...")
  
    print("=" * 60)
  
    search_in_memory_maps(pid, search_string)