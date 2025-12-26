import argparse
import os
import subprocess
import time
import socket
from prettytable import PrettyTable
from config import Config
from fofa_api import FofaAPI
from nmap_scanner import NmapScanner
from utils import *

# 常见端口-协议映射表
PORT_PROTOCOL_MAP = {
    "80": "tcp", "443": "tcp", "8080": "tcp", "8443": "tcp", "21": "tcp", "22": "tcp",
    "23": "tcp", "25": "tcp", "53": "tcp", "110": "tcp", "143": "tcp", "445": "tcp",
    "3389": "tcp", "1433": "tcp", "3306": "tcp", "5432": "tcp", "27017": "tcp",
    "123": "udp", "53": "udp", "67": "udp", "68": "udp", "161": "udp", "162": "udp",
    "500": "udp", "4500": "udp", "389": "udp", "137": "udp", "138": "udp"
}

def resolve_domain_to_ip(domain):
    """域名解析为IP（取第一个有效IPv4地址）"""
    try:
        ip_list = socket.getaddrinfo(domain, None, socket.AF_INET)
        for addr_info in ip_list:
            ip = addr_info[4][0]
            if is_valid_ip(ip):
                return ip
        return "解析失败"
    except socket.gaierror:
        return "解析失败"
    except Exception as e:
        print(f"域名解析异常：{str(e)}")
        return "解析失败"

def main():
    print_banner()

    # ============== 第一步：先构建argparse解析器并解析参数（解决args未定义问题） ==============
    parser = argparse.ArgumentParser(
        description='Nmap-Fofa 信息搜集工具（最终稳定版）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Nmap 扫描核心示例：
  1.  查看Nmap详细帮助：python main.py --nmap-help
  2.  查看所有Nmap扫描类型：python main.py --list-scans
  3.  探测C段存活主机：python main.py --target 192.168.1.0/24 --scan-type live_hosts
  4.  快速扫描单个IP：python main.py --target 111.26.xx.xx --scan-type quick_scan

Fofa 查询核心示例：
  1.  纯IP查询：python main.py --target 111.26.xx.xx --fofa
  2.  纯域名查询：python main.py --target xxxx.com --fofa
  3.  原生语法查询：python main.py --target 'title="后台" && port=8080' --fofa
        """
    )
    # 添加所有命令行参数
    parser.add_argument('--target', help='Nmap目标（IP/CIDR）；Fofa目标（纯IP/域名/原生语法）')
    parser.add_argument('--scan-type', help='Nmap扫描类型（--list-scans查看支持类型）')
    parser.add_argument('--fofa', action='store_true', help='使用Fofa API查询（独立于Nmap）')
    parser.add_argument('--list-scans', action='store_true', help='列出所有Nmap扫描类型（含详细说明）')
    parser.add_argument('--nmap-help', action='store_true', help='展示Nmap扫描详细使用指南')
    parser.add_argument('--config', nargs=2, metavar=('KEY', 'VALUE'), help='设置配置，示例：--config fofa.api_key 你的密钥')

    # 解析参数，生成args变量（关键：这一步必须在使用args之前执行）
    args = parser.parse_args()

    # ============== 第二步：后续逻辑（使用args变量，顺序不变） ==============
    # 初始化配置
    config = Config()
    nmap_config = config.get_nmap_config()
    fofa_config = config.get_fofa_config()

    # 处理配置设置
    if args.config:
        key, value = args.config
        if '.' in key:
            section, option = key.split('.')
            section = section.upper()
        else:
            print("❌ 配置格式错误！正确格式：--config 段名.键名 值，示例：--config fofa.api_key 你的密钥")
            return
        config.update_config(section, option, value)
        print(f"✅ 已更新配置：{key} = {value}")
        return

    # 展示Nmap专属帮助
    if args.nmap_help:
        print_nmap_help()
        return

    # 列出Nmap扫描类型
    if args.list_scans:
        print_scan_types()
        return

    # 初始化Nmap扫描器
    scanner = NmapScanner(nmap_path=nmap_config['path'], output_dir=nmap_config['output_dir'])

    # ========== Fofa查询逻辑（保留所有优化） ==========
    if args.fofa:
        # 检查Fofa配置
        if fofa_config['api_key'] == 'your_api_key_here' or fofa_config['email'] == 'your_email_here':
            print("❌ 请先配置Fofa API信息！正确命令：")
            print("  python main.py --config fofa.api_key 你的API密钥")
            print("  python main.py --config fofa.email 你的注册邮箱")
            return

        if not args.target:
            print("❌ 使用Fofa需要指定目标！示例：")
            print("  python main.py --target 111.26.69.164 --fofa")
            print("  python main.py --target jlbcwhg.com --fofa")
            return

        # 兼容纯IP/纯域名自动补全语法
        target = args.target
        fofa_query = ""
        if is_valid_ip(target):
            fofa_query = f"ip={target}"
            print(f"✅ 检测到纯IP，自动补全Fofa查询：{fofa_query}")
        elif not any(prefix in target for prefix in ["ip=", "domain=", "hostname=", "url=", "title=", "&&", "="]) and "." in target:
            fofa_query = f"domain={target}"
            print(f"✅ 检测到纯域名，自动补全Fofa查询：{fofa_query}")
        else:
            fofa_query = target
            print(f"✅ 使用Fofa原生查询：{fofa_query}")

        # 执行Fofa查询
        fofa = FofaAPI(fofa_config['email'], fofa_config['api_key'])
        fofa_result = fofa.search(fofa_query)

        # 格式化输出Fofa结果
        if fofa_result and 'results' in fofa_result:
            total = fofa_result.get('size', 0)
            print(f"\n✅ Fofa查询成功，共找到 {total} 条记录：")

            table = PrettyTable()
            table.field_names = ["IP地址", "端口", "协议", "域名", "操作系统", "标题", "服务器", "Banner信息"]

            for item in fofa_result['results']:
                # 处理IP/域名（域名自动解析IP）
                raw_ip_domain = item[0] if len(item) > 0 and item[0] else "-"
                pure_ip = "-"
                domain = item[3] if len(item) > 3 and item[3] and str(item[3]).strip() else "-"

                # 判断是否为IP/IP:端口/域名
                if is_valid_ip(str(raw_ip_domain).strip()):
                    pure_ip = str(raw_ip_domain).strip()
                elif ":" in str(raw_ip_domain):
                    ip_port_parts = str(raw_ip_domain).split(":")
                    if len(ip_port_parts) == 2 and is_valid_ip(ip_port_parts[0].strip()):
                        pure_ip = ip_port_parts[0].strip()
                else:
                    # 域名解析为IP
                    domain_str = str(raw_ip_domain).strip()
                    pure_ip = resolve_domain_to_ip(domain_str)
                    if domain == "-":
                        domain = domain_str

                # 处理端口
                port = "-"
                if ":" in str(raw_ip_domain):
                    ip_port_parts = str(raw_ip_domain).split(":")
                    if len(ip_port_parts) == 2 and ip_port_parts[1].strip().isdigit():
                        port = ip_port_parts[1].strip()
                if port == "-" and len(item) > 1 and item[1] and str(item[1]).strip().isdigit():
                    port = str(item[1]).strip()
                if port == "-" and len(item) > 2 and item[2] and str(item[2]).strip().isdigit():
                    port = str(item[2]).strip()

                # 处理协议（自动映射）
                protocol = item[2] if len(item) > 2 and item[2] and str(item[2]).strip() not in ["-", ""] else "-"
                if protocol != "-" and str(protocol).strip().isdigit():
                    protocol = PORT_PROTOCOL_MAP.get(str(protocol).strip(), "unknown")
                if protocol == "-" and port != "-":
                    protocol = PORT_PROTOCOL_MAP.get(port, "unknown")

                # 其他字段
                os_sys = item[4] if len(item) > 4 and item[4] and str(item[4]).strip() else "-"
                title = item[5] if len(item) > 5 and item[5] and str(item[5]).strip() else "-"
                server = item[8] if len(item) > 8 and item[8] and str(item[8]).strip() else "-"
                banner = item[9] if len(item) > 9 and item[9] and str(item[9]).strip() else "-"

                # 过长内容截断
                title = title[:30] + "..." if (isinstance(title, str) and len(title) > 30) else title
                banner = banner[:50] + "..." if (isinstance(banner, str) and len(banner) > 50) else banner

                table.add_row([pure_ip, port, protocol, domain, os_sys, title, server, banner])

            # 表格对齐
            table.align["IP地址"] = "l"
            table.align["标题"] = "l"
            table.align["Banner信息"] = "l"
            print(table)

            # 保存结果
            output_dir = nmap_config['output_dir'] if isinstance(nmap_config, dict) else "scan_results"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            fofa_save_file = os.path.join(
                output_dir,
                f"fofa_result_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            )

            with open(fofa_save_file, 'w', encoding='utf-8') as f:
                f.write(f"Fofa查询语句：{fofa_query}\n")
                f.write(f"查询时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"总记录数：{total}\n\n")
                f.write("="*120 + "\n")
                f.write(f"{'IP地址':<15} {'端口':<6} {'协议':<8} {'域名':<20} {'操作系统':<15} {'标题':<30} {'服务器':<15} {'Banner信息':<50}\n")
                f.write("="*120 + "\n")

                for item in fofa_result['results']:
                    # 重复解析逻辑
                    raw_ip_domain = item[0] if len(item) > 0 and item[0] else "-"
                    pure_ip = "-"
                    domain = item[3] if len(item) > 3 and item[3] and str(item[3]).strip() else "-"

                    if is_valid_ip(str(raw_ip_domain).strip()):
                        pure_ip = str(raw_ip_domain).strip()
                    elif ":" in str(raw_ip_domain):
                        ip_port_parts = str(raw_ip_domain).split(":")
                        if len(ip_port_parts) == 2 and is_valid_ip(ip_port_parts[0].strip()):
                            pure_ip = ip_port_parts[0].strip()
                    else:
                        domain_str = str(raw_ip_domain).strip()
                        pure_ip = resolve_domain_to_ip(domain_str)
                        if domain == "-":
                            domain = domain_str

                    # 端口处理
                    port = "-"
                    if ":" in str(raw_ip_domain):
                        ip_port_parts = str(raw_ip_domain).split(":")
                        if len(ip_port_parts) == 2 and ip_port_parts[1].strip().isdigit():
                            port = ip_port_parts[1].strip()
                    if port == "-" and len(item) > 1 and item[1] and str(item[1]).strip().isdigit():
                        port = str(item[1]).strip()
                    if port == "-" and len(item) > 2 and item[2] and str(item[2]).strip().isdigit():
                        port = str(item[2]).strip()

                    # 协议处理
                    protocol = item[2] if len(item) > 2 and item[2] and str(item[2]).strip() not in ["-", ""] else "-"
                    if protocol != "-" and str(protocol).strip().isdigit():
                        protocol = PORT_PROTOCOL_MAP.get(str(protocol).strip(), "unknown")
                    if protocol == "-" and port != "-":
                        protocol = PORT_PROTOCOL_MAP.get(port, "unknown")

                    # 其他字段
                    os_sys = item[4] if len(item) > 4 and item[4] and str(item[4]).strip() else "-"
                    title = item[5] if len(item) > 5 and item[5] and str(item[5]).strip() else "-"
                    server = item[8] if len(item) > 8 and item[8] and str(item[8]).strip() else "-"
                    banner = item[9] if len(item) > 9 and item[9] and str(item[9]).strip() else "-"

                    # 截断
                    title = title[:30] + "..." if (isinstance(title, str) and len(title) > 30) else title
                    banner = banner[:50] + "..." if (isinstance(banner, str) and len(banner) > 50) else banner

                    f.write(f"{pure_ip:<15} {port:<6} {protocol:<8} {domain:<20} {os_sys:<15} {title:<30} {server:<15} {banner:<50}\n")

            print(f"\n✅ Fofa结果已保存至：{fofa_save_file}")
        else:
            print("❌ Fofa查询无结果或查询失败！")
        return
    def call_grep_cut_command():
        # 你的原始命令，完整保留
        cmd = 'grep "Status: Up" ./scan_results/Discovery.gnmap | cut -f 2 -d \' \' > ./scan_results/liveHosts.txt'

        try:
            # 执行命令：shell=True 开启Shell语法解析
            # capture_output=True：捕获命令输出（可选，此处命令已重定向到文件，捕获的是无额外输出）
            # text=True：以文本模式处理输出（默认是字节流）
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,  # 命令执行失败（返回非0状态码）时抛出异常
                capture_output=True,
                text=True
            )

            # 验证文件是否生成
            if os.path.exists('./scan_results/liveHosts.txt'):
                print(f"✅ 命令执行成功！已生成文件：./scan_results/liveHosts.txt")
            else:
                print(f"⚠️  命令执行返回正常，但未找到生成的文件")
        except subprocess.CalledProcessError as e:
            # 命令执行失败（如文件不存在、grep无匹配结果）
            print(f"❌ 命令执行失败！错误信息：{e.stderr}")
        except Exception as e:
            # 其他异常（如权限不足）
            print(f"❌ 未知异常：{str(e)}")
    # ========== Nmap扫描逻辑（保留所有优化） ==========
    if not args.target:
        print("❌ 未指定目标！")
        print("📌 Nmap扫描使用指南：")
        print("  1.  查看Nmap详细帮助：python main.py --nmap-help")
        print("  2.  查看扫描类型：python main.py --list-scans")
        print("  3.  最小化示例：python main.py --target 111.26.xx.xx --scan-type quick_scan")
        return

    if not (is_valid_cidr(args.target) or is_valid_ip(args.target)):
        print(f"❌ 无效的Nmap目标格式：{args.target}")
        print("📌 Nmap仅支持「IP地址」（如111.26.xx.xx）或「CIDR C段」（如192.168.1.0/24）")
        return

    if not args.scan_type:
        print(f"❌ 未指定Nmap扫描类型！目标：{args.target}")
        print("📌 解决方案：")
        print("  1.  查看所有支持的扫描类型：python main.py --list-scans")
        print("  2.  补充扫描类型参数，示例：--scan-type live_hosts/quick_scan")
        return

    if is_valid_ip(args.target):
        cidr = extract_cidr_from_ip(args.target)
        print(f"✅ 检测到单个IP，所属C段：{cidr}")

    try:
        result, _ = scanner.scan(args.target, args.scan_type)
        if result:
            print(f"\n✅ Nmap扫描完成！目标：{args.target}，扫描类型：{args.scan_type}")
            scanner.display_results(result)
        else:
            print(f"❌ Nmap扫描失败！目标：{args.target}，扫描类型：{args.scan_type}")
        if not os.path.exists('./scan_results'):
            os.makedirs('./scan_results')
            print(f"✅ 已创建目录：./scan_results")
        if not os.path.exists('./scan_results/liveHosts.txt'):

            call_grep_cut_command()
        else:
            print(f"✅ 已存在文件：./scan_results/liveHosts.txt")

    except Exception as e:
        print(f"❌ Nmap扫描异常：{str(e)}")


if __name__ == "__main__":
    main()
