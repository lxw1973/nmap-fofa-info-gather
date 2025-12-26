import subprocess
import os


def extract_network_from_gnmap(gnmap_file_path):
    """
    从Discovery.gnmap文件中提取扫描的网络地址（如192.168.1.0/24）
    优先从gnmap文件头部提取目标网段，提取失败返回默认值
    """
    network_addr = "unknown_network"  # 兜底默认值
    try:
        # 读取gnmap文件内容
        with open(gnmap_file_path, 'r', encoding='utf-8') as f:
            # 逐行读取，优先解析头部的扫描目标信息
            for line in f:
                line = line.strip()
                # nmap的gnmap文件头部通常包含扫描目标（如：nmap -sn -oG Discovery.gnmap 192.168.1.0/24）
                if line.startswith("# Nmap") and " as: " in line:
                    # 分割获取扫描命令部分，提取最后一个参数（即目标网段）
                    cmd_parts = line.split(" as: ")[-1].split()
                    if cmd_parts:
                        # 取命令的最后一个参数作为网络地址
                        network_addr = cmd_parts[-1]
                        break
                # 若头部未提取到，从存活主机行提取IP并简化为网段（备用方案）
                elif "Status: Up" in line and "Host: " in line:
                    ip_part = line.split("Host: ")[1].split()[0]
                    # 简单将IP最后一段改为0/24（示例逻辑，可根据实际需求调整）
                    ip_segments = ip_part.split(".")
                    if len(ip_segments) == 4:
                        network_addr = f"{ip_segments[0]}.{ip_segments[1]}.{ip_segments[2]}.0/24"
                    break
    except FileNotFoundError:
        print(f"⚠️  未找到gnmap文件：{gnmap_file_path}，使用默认网络名称")
    except Exception as e:
        print(f"⚠️  提取网络地址失败：{str(e)}，使用默认网络名称")
    return network_addr


def sanitize_filename_characters(original_str):
    """
    清理文件名中的非法字符（核心：替换/为_，同时处理其他常见非法字符）
    支持跨平台（Linux/Windows）兼容
    """
    # 定义文件系统非法字符（Linux: /；Windows: \/:*?"<>|）
    illegal_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    sanitized_str = original_str
    for char in illegal_chars:
        sanitized_str = sanitized_str.replace(char, '_')  # 替换为下划线（可自定义为-）
    return sanitized_str


def call_grep_cut_command():
    # 定义文件路径
    gnmap_file = './scan_results/Discovery.gnmap'
    scan_dir = './scan_results'

    # 第一步：提取网络地址
    network_addr = extract_network_from_gnmap(gnmap_file)

    # 第二步：清理网络地址中的非法字符（关键修复步骤）
    sanitized_network = sanitize_filename_characters(network_addr)

    # 第三步：拼接新的输出文件名（清理后的网络地址_liveHosts.txt）
    output_filename = f"{sanitized_network}_liveHosts.txt"
    output_file_path = os.path.join(scan_dir, output_filename)  # 完整输出文件路径

    # 构造带新文件名的命令
    cmd = f'grep "Status: Up" {gnmap_file} | cut -f 2 -d \' \' > {output_file_path}'

    try:
        # 执行命令：shell=True 开启Shell语法解析
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,  # 命令执行失败（返回非0状态码）时抛出异常
            capture_output=True,
            text=True
        )

        # 验证文件是否生成
        if os.path.exists(output_file_path):
            print(f"✅ 命令执行成功！已生成文件：{output_file_path}")
        else:
            print(f"⚠️  命令执行返回正常，但未找到生成的文件：{output_file_path}")
    except subprocess.CalledProcessError as e:
        # 命令执行失败（如文件不存在、grep无匹配结果）
        print(f"❌ 命令执行失败！错误信息：{e.stderr}")
    except Exception as e:
        # 其他异常（如权限不足）
        print(f"❌ 未知异常：{str(e)}")


# 调用函数
if __name__ == "__main__":
    # 确保scan_results目录存在（避免目录不存在导致命令失败）
    scan_dir = './scan_results'
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)
        print(f"✅ 已创建目录：{scan_dir}")

    call_grep_cut_command()