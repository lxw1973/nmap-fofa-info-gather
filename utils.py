import ipaddress
import re


def is_valid_cidr(cidr):
    """验证CIDR格式是否有效"""
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_ip(ip):
    """验证IP地址是否有效"""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    for part in match.groups():
        if int(part) < 0 or int(part) > 255:
            return False
    return True


def extract_cidr_from_ip(ip):
    """从IP地址提取C段（如192.168.1.100 -> 192.168.1.0/24）"""
    if not is_valid_ip(ip):
        return None
    parts = ip.split('.')[:3]
    return f"{'.'.join(parts)}.0/24"


def print_banner():
    """打印工具横幅"""
    banner = """
    ==================================================
    ||              Nmap-Fofa 信息搜集工具          ||
    ||         集成Nmap扫描与Fofa API查询功能       ||
    ||         2025-12-25    By:Bruce_liu           || 
    ==================================================
    """
    print(banner)


def print_scan_types():
    """打印支持的扫描类型（增强详细说明，提升可读性）"""
    print("\n=================== Nmap 支持的扫描类型 ===================")
    print("  格式说明：扫描类型代码 | 扫描名称 | 适用场景 | 特点")
    print("===========================================================")
    scan_types = [
        ("live_hosts", "存活主机探测", "内网C段/外网网段", "仅探测主机是否存活，不扫描端口，速度快"),
        ("quick_scan", "快速端口扫描", "初步信息搜集", "扫描1-1000号端口，平衡速度与信息密度"),
        ("full_port", "全端口扫描", "全面端口探测", "扫描0-65535所有端口，信息完整，速度中等"),
        ("deep_scan", "深度全端口扫描", "精准探测", "全端口+3次重传，减少漏扫，速度较慢"),
        ("ultra_fast", "超快速扫描", "紧急快速摸排", "T5速度+100ms超时，风险高（易漏扫）"),
        ("common_ports", "常用端口扫描", "常规服务探测", "扫描默认常用端口，兼顾速度与实用性"),
        ("service_ports", "常见服务端口扫描", "针对性服务探测", "仅扫描21/22/80/443等常见服务端口"),
        ("web_ports", "Web服务端口扫描", "网站探测", "仅扫描80/443/8080等Web相关端口"),
        ("db_ports", "数据库端口扫描", "数据库探测", "仅扫描1433/3306/27017等数据库端口"),
        ("os_detect", "操作系统探测", "系统识别", "仅探测目标操作系统类型，不完整扫描端口"),
        ("full_os_detect", "全端口系统探测", "精准系统识别", "全端口扫描+操作系统探测，信息全面"),
        ("version_detect", "服务版本探测", "服务识别", "探测开放端口对应的服务版本信息"),
        ("full_version", "全端口版本探测", "精准服务识别", "全端口扫描+服务版本探测，信息详细"),
        ("complete_scan", "完整综合扫描", "深度渗透测试", "全端口+系统+服务+默认脚本，最全面，耗时最长"),
        ("stealth_scan", "慢速隐蔽扫描", "规避防火墙/IDS", "T2速度+5s延迟，不易被检测，速度极慢"),
        ("random_scan", "随机化扫描", "规避简单防护", "随机打乱主机/端口扫描顺序，迷惑防护设备"),
        ("advanced_stealth", "高级隐蔽扫描", "高难度规避", "分片+MAC欺骗+低速率，对抗高级防护"),
        ("smb_ghost", "SMB Ghost漏洞扫描", "漏洞探测", "仅扫描445端口+smb-ghost脚本，针对性检测漏洞")
    ]

    # 格式化输出，更易阅读
    for scan_code, scan_name, scene, feature in scan_types:
        print(f"  {scan_code:<15} | {scan_name:<12} | {scene:<12} | {feature}")
    print("\n===========================================================")
    print("  提示：扫描类型可直接跟在 --scan-type 后使用，如 --scan-type live_hosts")
    print("===========================================================\n")


def print_nmap_help():
    """打印Nmap专属详细帮助指南"""
    nmap_help_text = """
=================== Nmap 扫描 详细使用指南 ===================
1.  适用范围：仅支持 IP 地址（如111.26.xx.xx）或 C段（如192.168.1.0/24）
2.  必选参数：--target（指定目标） + --scan-type（指定扫描类型）
3.  查看扫描类型：python main.py --list-scans
4.  常用示例：
    a.  探测内网C段存活主机：
        python main.py --target 192.168.1.0/24 --scan-type live_hosts
    b.  快速扫描单个IP常用端口：
        python main.py --target 111.26.xx.xx --scan-type quick_scan
    c.  全端口深度扫描C段：
        python main.py --target 192.168.1.0/24 --scan-type deep_scan
    d.  Web服务针对性扫描：
        python main.py --target 111.26.xx.xx --scan-type web_ports
5.  结果保存：所有扫描结果自动保存至 scan_results 目录下
6.  注意事项：
    a.  外网扫描建议使用 quick_scan/web_ports，避免触发目标防护
    b.  内网扫描可使用 full_port/complete_scan，获取更全面信息
    c.  隐蔽扫描（stealth_scan）速度极慢，适合高精度渗透测试
=============================================================
    """
    print(nmap_help_text)