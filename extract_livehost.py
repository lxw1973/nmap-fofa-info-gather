import subprocess
import os


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


# 调用函数
if __name__ == "__main__":
    # 确保scan_results目录存在（避免目录不存在导致命令失败）
    if not os.path.exists('./scan_results'):
        os.makedirs('./scan_results')
        print(f"✅ 已创建目录：./scan_results")

    call_grep_cut_command()