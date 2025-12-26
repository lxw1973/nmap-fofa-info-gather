import nmap
import os
import time
import subprocess  # 用于执行系统命令
from prettytable import PrettyTable


class NmapScanner:
    def __init__(self, nmap_path='nmap', output_dir='scan_results'):
        self.nm = nmap.PortScanner(nmap_search_path=[nmap_path])
        self.output_dir = output_dir
        # 固定文件名（与你的命令完全一致）
        self.discovery_gnmap = os.path.join(self.output_dir, "Discovery.gnmap")
        self.live_hosts_txt = os.path.join(self.output_dir, "liveHosts.txt")

        # 创建输出目录
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # 常用扫描命令模板（重点修改live_hosts：固定输出为Discovery.gnmap）
        self.scan_templates = {
            # 严格匹配用户指定命令：-sn -v -T4 -oG Discovery.gnmap
            'live_hosts': f'-sn -v -T4 -oG {self.discovery_gnmap}',
            'quick_scan': '-sS -T4 -p 1-1000 -oN {output_file}.txt',
            'full_port': '-sS -v -T4 -Pn -p 0-65535 -oN {output_file}.txt',
            'deep_scan': '-sS -T3 -p 0-65535 --max-retries 3 -oN {output_file}.txt',
            'ultra_fast': '-sS -T5 -p 0-65535 --max-rtt-timeout 100ms',
            'common_ports': '-sS -T4 -Pn -oG {output_file}.gnmap',
            'service_ports': '-sS -p 21,22,23,25,53,80,110,143,443,445,3389 -oN {output_file}.txt',
            'web_ports': '-sS -p 80,443,8080,8443,8000,3000,9000 -oN {output_file}.txt',
            'db_ports': '-sS -p 1433,1521,3306,5432,27017,6379 -oN {output_file}.txt',
            'os_detect': '-O -T4 -Pn -oG {output_file}.gnmap',
            'full_os_detect': '-sS -O -p 0-65535 -oN {output_file}.txt',
            'version_detect': '-sV -T4 -Pn -oG {output_file}.gnmap',
            'full_version': '-sS -sV -p 0-65535 -oN {output_file}.txt',
            'complete_scan': '-sS -sV -O -p 0-65535 --script=default -oA {output_file}',
            'stealth_scan': '-sS -T2 --scan-delay 5s --max-rate 10 -p 0-65535 -oN {output_file}.txt',
            'random_scan': '-sS --randomize-hosts -p 0-65535 -oN {output_file}.txt',
            'advanced_stealth': '-sS -f --mtu 24 --spoof-mac 0 -p 0-65535 -oN {output_file}.txt',
            'smb_ghost': '-p445 -v --script smb-ghost -oN {output_file}.txt'
        }

    def generate_output_filename(self, scan_type, target):
        """生成非live_hosts类型的动态输出文件名（不带后缀）"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        target_clean = target.replace('/', '_').replace(':', '_')
        return os.path.join(self.output_dir, f"{scan_type}_{target_clean}_{timestamp}")

    def scan(self, target, scan_type, args=None):
        """
        执行扫描
        :param target: 目标IP或C段
        :param scan_type: 扫描类型
        :param args: 额外参数
        :return: 扫描结果、输出文件基础路径（live_hosts类型返回固定文件路径）
        """
        if scan_type not in self.scan_templates:
            print(f"错误：未知的扫描类型 {scan_type}")
            return None, None

        # 构建扫描命令
        if scan_type == 'live_hosts':
            # live_hosts类型：使用固定命令（已包含Discovery.gnmap路径）
            base_command = self.scan_templates[scan_type]
            output_base = self.discovery_gnmap
        else:
            output_base = self.generate_output_filename(scan_type, target)
            base_command = self.scan_templates[scan_type].format(
                output_file=output_base
            )

        # 添加额外参数
        if args:
            base_command += f" {args}"

        try:
            print(f"开始扫描 {target}，类型：{scan_type}")
            print(f"执行命令：nmap {base_command} {target}")

            self.nm.scan(hosts=target, arguments=base_command)
            if scan_type == 'live_hosts':
                print(f"扫描完成，固定文件已保存至：{self.discovery_gnmap}")
            else:
                print(f"扫描完成，结果已保存至 {output_base} 相关文件")
            return self.nm, output_base
        except Exception as e:
            print(f"扫描出错: {str(e)}")
            return None, None

    def extract_live_hosts_by_command(self):
        """
        方法1：执行你指定的系统命令，过滤存活主机
        命令：grep "Status: Up" Discovery.gnmap | cut -f 2 -d ' ' > liveHosts.txt
        """
        try:
            # 切换到输出目录（避免文件路径问题）
            os.chdir(self.output_dir)
            # 构建命令（兼容Linux/Mac，使用shell=True执行管道命令）
            grep_cut_cmd = 'grep "Status: Up" Discovery.gnmap | cut -f 2 -d \' \' > liveHosts.txt'
            # 执行命令
            subprocess.run(grep_cut_cmd, shell=True, check=True, capture_output=True, text=True)
            print(f"✅ 已执行命令过滤存活主机：{grep_cut_cmd}")
            print(f"✅ 存活主机文件已生成：{self.live_hosts_txt}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️  系统命令执行失败（可能无grep/cut工具，将使用Python内置逻辑）：{str(e)}")
            return False
        except Exception as e:
            print(f"⚠️  命令执行异常：{str(e)}")
            return False

    def extract_live_hosts_by_python(self):
        """
        方法2：Python内置逻辑解析，兼容所有系统（兜底方案）
        过滤规则：只保留包含"Status: Up"的行，提取第2个字段（IP），剔除Down状态
        """
        try:
            if not os.path.exists(self.discovery_gnmap):
                print(f"错误：未找到 {self.discovery_gnmap}，无法提取存活主机")
                return False

            live_ips = []
            # 读取gnmap文件
            with open(self.discovery_gnmap, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # 逐行解析
            for line in lines:
                line = line.strip()
                # 过滤出Status: Up的行，剔除Down状态
                if "Status: Up" in line and "Status: Down" not in line:
                    # 按空格分割，取第2个字段（IP）
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        # 简单验证IP格式（避免无效内容）
                        if '.' in ip and len(ip.split('.')) == 4:
                            if ip not in live_ips:  # 去重
                                live_ips.append(ip)

            # 写入liveHosts.txt
            with open(self.live_hosts_txt, 'w', encoding='utf-8') as f:
                for ip in live_ips:
                    f.write(f"{ip}\n")

            print(f"✅ Python内置逻辑过滤完成，共找到 {len(live_ips)} 台存活主机")
            print(f"✅ 存活主机文件已生成：{self.live_hosts_txt}")
            return True
        except Exception as e:
            print(f"错误：Python解析过滤失败：{str(e)}")
            return False

    def extract_live_hosts(self):
        """
        统一入口：优先执行系统命令，失败则使用Python内置逻辑
        """
        print(f"\n开始过滤存活主机（仅保留Status: Up，剔除Status: Down）...")
        # 先尝试系统命令
        cmd_success = self.extract_live_hosts_by_command()
        if not cmd_success:
            # 命令失败，使用Python兜底
            self.extract_live_hosts_by_python()

    def scan_cidr(self, cidr, scan_type='quick_scan'):
        """扫描整个C段"""
        result, _ = self.scan(cidr, scan_type)
        return result

    def detect_live_hosts(self, cidr):
        """
        完整流程：扫描生成Discovery.gnmap → 自动过滤生成liveHosts.txt
        """
        # 步骤1：执行存活扫描，生成 Discovery.gnmap
        scan_result, _ = self.scan(cidr, 'live_hosts')
        if not scan_result:
            print("存活主机扫描失败，无法生成Discovery.gnmap")
            return []

        # 步骤2：自动过滤存活主机，生成 liveHosts.txt（核心新增）
        self.extract_live_hosts()

        # 步骤3：返回存活主机列表
        if os.path.exists(self.live_hosts_txt):
            with open(self.live_hosts_txt, 'r', encoding='utf-8') as f:
                live_ips = [line.strip() for line in f.readlines() if line.strip()]
            return live_ips
        else:
            return []

    def display_results(self, scan_result):
        """展示扫描结果"""
        if not scan_result:
            print("没有扫描结果可展示")
            return

        table = PrettyTable()
        table.field_names = ["IP地址", "状态", "开放端口", "操作系统", "服务信息"]

        for host in scan_result.all_hosts():
            state = scan_result[host].state()
            ports = []
            services = []

            for proto in scan_result[host].all_protocols():
                lport = scan_result[host][proto].keys()
                for port in sorted(lport):
                    ports.append(str(port))
                    service = scan_result[host][proto][port]['name']
                    version = scan_result[host][proto][port]['version']
                    services.append(f"{port}/{service}/{version}")

            os_info = scan_result[host].get('osmatch', [{}])[0].get('name', '未知') if 'osmatch' in scan_result[
                host] else '未知'
            port_str = ', '.join(ports) if ports else '无'
            service_str = ', '.join(services) if services else '无'

            table.add_row([host, state, port_str, os_info, service_str])

        print(table)