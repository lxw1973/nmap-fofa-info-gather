import requests
import json
import base64  # 必须导入base64模块


class FofaAPI:
    def __init__(self, email, api_key):
        self.email = email
        self.api_key = api_key
        self.base_url = "https://fofa.info/api/v1"

    def _get_auth_params(self):
        """获取Fofa认证参数"""
        return {
            "email": self.email,
            "key": self.api_key
        }

    def search(self, query, page=1, size=100):
        """
        通用Fofa搜索（支持原生语法，兼容纯IP/纯域名直接查询）
        :param query: Fofa查询语句（可直接传IP、域名或原生语法）
        :param page: 页码
        :param size: 每页数量
        :return: 搜索结果字典
        """
        try:
            # 修复核心编码错误：使用base64模块的b64encode方法
            query_bytes = query.encode('utf-8')  # 转为字节流
            query_base64 = base64.b64encode(query_bytes).decode('utf-8')  # 先编码再解码为字符串

            params = self._get_auth_params()
            params.update({
                "qbase64": query_base64,
                "page": page,
                "size": size
            })

            # 发送请求，设置超时时间
            response = requests.get(
                f"{self.base_url}/search/all",
                params=params,
                timeout=30
            )
            response.raise_for_status()  # 抛出HTTP错误
            result = json.loads(response.text)

            # 捕获Fofa API返回的业务错误
            if result.get("error"):
                print(f"Fofa业务错误：{result.get('errmsg', '未知错误')}")
                return None
            return result

        except requests.exceptions.Timeout:
            print("错误：Fofa API请求超时，请检查网络连接")
            return None
        except requests.exceptions.HTTPError as e:
            print(f"错误：Fofa API HTTP请求失败 - {e}")
            return None
        except Exception as e:
            print(f"错误：Fofa搜索异常 - {str(e)}")
            return None

    def get_ip_from_cidr(self, cidr):
        """兼容原有功能：C段查询"""
        query = f"ip={cidr}"
        return self.search(query)