import configparser
import os


class Config:
    def __init__(self, config_file="config.ini"):
        self.config_file = config_file
        self.config = configparser.ConfigParser()

        # 如果配置文件不存在，创建默认配置
        if not os.path.exists(self.config_file):
            self._create_default_config()

        self.config.read(self.config_file)

    def _create_default_config(self):
        self.config['FOFA'] = {
            'api_key': 'your_api_key_here',
            'email': 'your_email_here'
        }
        self.config['NMAP'] = {
            'path': 'nmap',  # 默认假设nmap在环境变量中
            'output_dir': 'scan_results'
        }

        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get_fofa_config(self):
        return {
            'api_key': self.config.get('FOFA', 'api_key'),
            'email': self.config.get('FOFA', 'email')
        }

    def get_nmap_config(self):
        return {
            'path': self.config.get('NMAP', 'path'),
            'output_dir': self.config.get('NMAP', 'output_dir')
        }

    def update_config(self, section, key, value):
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value

        with open(self.config_file, 'w') as f:
            self.config.write(f)