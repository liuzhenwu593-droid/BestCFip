#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare IP地址收集器 - 完整版
从多个源收集Cloudflare IPv4和IPv6地址，支持国家过滤
"""

import requests
import re
import os
import ipaddress
import random
import uuid
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class CloudflareIPCollector:
    """Cloudflare IP地址收集器 - 支持国家过滤"""
    
    def __init__(self, 
                 port: str = '8443', 
                 exclude_countries: List[str] = None,
                 include_countries: List[str] = None,
                 timeout: int = 10, 
                 max_retries: int = 3,
                 enable_ipv6_location: bool = False):
        """
        初始化收集器
        
        Args:
            port: 目标端口号
            exclude_countries: 要排除的国家列表 (如 ['US', 'JP'])
            include_countries: 只包含这些国家 (如 ['CN', 'HK', 'SG'])
            timeout: 请求超时时间（秒）
            max_retries: 最大重试次数
            enable_ipv6_location: 是否启用IPv6地理位置查询（较慢）
        """
        self.port = port
        self.exclude_countries = exclude_countries or []
        self.include_countries = include_countries or []
        self.timeout = timeout
        self.max_retries = max_retries
        self.enable_ipv6_location = enable_ipv6_location
        
        # 显示过滤条件
        if self.exclude_countries:
            logger.info(f"🚫 排除国家: {', '.join(self.exclude_countries)}")
        if self.include_countries:
            logger.info(f"✅ 只包含国家: {', '.join(self.include_countries)}")
        
        # IP地址数据源
        self.sources = {
            'https://api.uouin.com/cloudflare.html': 'Uouin',
            'https://ip.164746.xyz': 'ZXW',
            'https://ipdb.api.030101.xyz/?type=bestcf': 'IPDB',
            'https://www.wetest.vip/page/cloudflare/address_v6.html': 'WeTestV6',
            'https://ipdb.api.030101.xyz/?type=bestcfv6': 'IPDBv6',
            'https://cf.090227.xyz/CloudFlareYes': 'CFYes',
            'https://ip.haogege.xyz': 'HaoGG',
            'https://vps789.com/openApi/cfIpApi': 'VPS',
            'https://www.wetest.vip/page/cloudflare/address_v4.html': 'WeTest',
            'https://addressesapi.090227.xyz/ct': 'CMLiuss',
            'https://addressesapi.090227.xyz/cmcc-ipv6': 'CMLiussv6',
            'https://raw.githubusercontent.com/xingpingcn/enhanced-FaaS-in-China/refs/heads/main/Cf.json': 'FaaS'
        }
        
        # 请求头
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # 存储结果
        self.ipv4_data: Dict[str, str] = {}
        self.ipv6_data: Dict[str, str] = {}
        
        # 统计信息
        self.stats = {
            'total_sources': len(self.sources),
            'success_sources': 0,
            'failed_sources': 0,
            'ipv4_count': 0,
            'ipv6_count': 0,
            'filtered_count': 0,
            'errors': []
        }
        
        # 创建带重试机制的session
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """创建带有重试机制的requests会话"""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _fetch_content(self, url: str) -> Optional[str]:
        """
        获取URL内容
        
        Args:
            url: 要请求的URL
            
        Returns:
            响应内容文本，失败返回None
        """
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout,
                verify=True
            )
            response.raise_for_status()
            
            # 尝试检测编码
            if response.encoding is None:
                response.encoding = 'utf-8'
            
            return response.text
            
        except requests.exceptions.Timeout:
            error_msg = f"请求超时: {url}"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
            return None
            
        except requests.exceptions.ConnectionError:
            error_msg = f"连接错误: {url}"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
            return None
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP错误 {url}: {e}"
            logger.warning(error_msg)
            self.stats['errors'].append(error_msg)
            return None
            
        except Exception as e:
            error_msg = f"请求失败 {url}: {e}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            return None
    
    def _parse_content(self, content: str, url: str) -> str:
        """
        解析网页内容，提取纯文本
        
        Args:
            content: 原始内容
            url: 来源URL
            
        Returns:
            提取后的文本内容
        """
        # 处理JSON格式
        if url.endswith('.json') or 'json' in url.lower():
            try:
                data = json.loads(content)
                # 递归提取所有字符串值
                text_parts = []
                self._extract_json_text(data, text_parts)
                return '\n'.join(text_parts)
            except json.JSONDecodeError:
                logger.warning(f"JSON解析失败: {url}")
                return content
        
        # 处理纯文本
        if url.endswith('.txt'):
            return content
        
        # 处理HTML
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # 移除script和style标签
            for script in soup(["script", "style"]):
                script.decompose()
            
            # 查找表格和列表
            elements = soup.find_all(['tr', 'li', 'td', 'p', 'pre', 'code'])
            
            if elements:
                text = '\n'.join(el.get_text(strip=True) for el in elements)
            else:
                # 如果没有表格/列表，获取所有文本
                text = soup.get_text(separator='\n', strip=True)
            
            return text
            
        except Exception as e:
            logger.error(f"HTML解析失败 {url}: {e}")
            return content
    
    def _extract_json_text(self, data, text_parts: List[str]):
        """递归提取JSON中的所有字符串值"""
        if isinstance(data, dict):
            for value in data.values():
                self._extract_json_text(value, text_parts)
        elif isinstance(data, list):
            for item in data:
                self._extract_json_text(item, text_parts)
        elif isinstance(data, str):
            text_parts.append(data)
    
    def _is_valid_country(self, country: str) -> bool:
        """
        检查国家是否有效
        
        Args:
            country: 国家代码
            
        Returns:
            True表示有效，False表示被过滤
        """
        if not country or country == 'UNKNOWN':
            return False
        
        # 先检查排除列表
        if self.exclude_countries and country in self.exclude_countries:
            return False
        
        # 再检查包含列表
        if self.include_countries and country not in self.include_countries:
            return False
        
        return True
    
    def _get_ip_location(self, ip: str) -> Tuple[str, bool]:
        """
        获取IP的地理位置信息并检查有效性
        
        Args:
            ip: IP地址
            
        Returns:
            (国家代码, 是否有效)
        """
        try:
            response = self.session.get(
                f"https://ipinfo.io/{ip}/country",
                headers=self.headers,
                timeout=5
            )
            if response.status_code == 200:
                country = response.text.strip()
                is_valid = self._is_valid_country(country)
                return country, is_valid
            return 'UNKNOWN', False
        except Exception:
            return 'UNKNOWN', False
    
    def _get_ip_location_detailed(self, ip: str) -> Tuple[str, str, bool]:
        """
        获取IP的详细地理位置信息
        
        Args:
            ip: IP地址
            
        Returns:
            (国家代码, 城市, 是否有效)
        """
        try:
            response = self.session.get(
                f"https://ipinfo.io/{ip}/json",
                headers=self.headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                country = data.get('country', 'UNKNOWN')
                city = data.get('city', '')
                is_valid = self._is_valid_country(country)
                return country, city, is_valid
            return 'UNKNOWN', '', False
        except Exception:
            return 'UNKNOWN', '', False
    
    def _extract_ips_from_text(self, text: str, source_name: str):
        """
        从文本中提取IPv4和IPv6地址
        
        Args:
            text: 要提取的文本
            source_name: 来源名称
        """
        # 提取IPv4地址
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv4_set = set(re.findall(ipv4_pattern, text))
        
        for ip in ipv4_set:
            try:
                if ipaddress.ip_address(ip).version == 4:
                    ip_with_port = f"{ip}:{self.port}"
                    if ip_with_port not in self.ipv4_data:
                        # 获取地理位置并检查是否有效
                        country, is_valid = self._get_ip_location(ip)
                        
                        # 如果无效，跳过
                        if not is_valid:
                            self.stats['filtered_count'] += 1
                            continue
                        
                        comment = f"{country}-{uuid.uuid4().hex[27:]}{random.randint(0, 10)}"
                        self.ipv4_data[ip_with_port] = comment
            except ValueError:
                continue
        
        # 提取IPv6地址
        ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' \
                      r'(?:[0-9a-fA-F]{1,4}:){1,7}:|' \
                      r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' \
                      r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|' \
                      r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|' \
                      r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|' \
                      r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|' \
                      r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|' \
                      r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|' \
                      r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|' \
                      r'::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
        
        ipv6_set = set(re.findall(ipv6_pattern, text))
        
        for ip in ipv6_set:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 6:
                    ip_with_port = f"[{ip_obj.compressed}]:{self.port}"
                    if ip_with_port not in self.ipv6_data:
                        # IPv6地理位置查询（可选，较慢）
                        if self.enable_ipv6_location:
                            country, _, is_valid = self._get_ip_location_detailed(ip)
                            if not is_valid:
                                self.stats['filtered_count'] += 1
                                continue
                            comment = f"{country}-{uuid.uuid4().hex[27:]}{random.randint(0, 10)}"
                        else:
                            comment = f"{source_name}-{uuid.uuid4().hex[27:]}{random.randint(0, 10)}"
                        
                        self.ipv6_data[ip_with_port] = comment
            except ValueError:
                continue
    
    def collect(self):
        """从所有源收集IP地址"""
        logger.info("=" * 60)
        logger.info("🚀 开始收集Cloudflare IP地址")
        logger.info("=" * 60)
        
        for url, source_name in self.sources.items():
            logger.info(f"📡 正在处理: {source_name} ({url})")
            
            content = self._fetch_content(url)
            if content is None:
                self.stats['failed_sources'] += 1
                continue
            
            self.stats['success_sources'] += 1
            
            # 解析内容
            text = self._parse_content(content, url)
            
            # 提取IP地址
            self._extract_ips_from_text(text, source_name)
            
            logger.info(f"   📊 当前已收集: IPv4={len(self.ipv4_data)}, IPv6={len(self.ipv6_data)}, 已过滤={self.stats['filtered_count']}")
    
    def _validate_ips(self):
        """验证IP地址的有效性"""
        # 验证IPv4
        valid_ipv4 = {}
        for ip_with_port, comment in self.ipv4_data.items():
            ip = ip_with_port.split(':')[0]
            try:
                ipaddress.ip_address(ip)
                valid_ipv4[ip_with_port] = comment
            except ValueError:
                continue
        
        # 验证IPv6
        valid_ipv6 = {}
        for ip_with_port, comment in self.ipv6_data.items():
            ip = ip_with_port.strip('[]').split(']:')[0]
            try:
                ipaddress.ip_address(ip)
                valid_ipv6[ip_with_port] = comment
            except ValueError:
                continue
        
        self.ipv4_data = valid_ipv4
        self.ipv6_data = valid_ipv6
    
    def save_results(self, output_dir: str = '.'):
        """
        保存结果到文件
        
        Args:
            output_dir: 输出目录
        """
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        
        # 生成时间戳
        beijing_time = datetime.utcnow() + timedelta(hours=8)
        timestamp = beijing_time.strftime('%Y%m%d_%H%M')
        
        # 验证IP
        self._validate_ips()
        
        # 更新统计
        self.stats['ipv4_count'] = len(self.ipv4_data)
        self.stats['ipv6_count'] = len(self.ipv6_data)
        
        # 构建过滤信息
        filter_info = ""
        if self.exclude_countries:
            filter_info += f"排除: {', '.join(self.exclude_countries)} "
        if self.include_countries:
            filter_info += f"包含: {', '.join(self.include_countries)}"
        if not filter_info:
            filter_info = "无过滤"
        
        # 保存IPv4
        ipv4_path = os.path.join(output_dir, 'ipv4.txt')
        try:
            with open(ipv4_path, 'w', encoding='utf-8') as f:
                f.write(f"ipv4.list.updated.at#Upd{timestamp}\n")
                f.write(f"# 总数: {len(self.ipv4_data)} 个IP\n")
                f.write(f"# 来源: {self.stats['success_sources']} 个数据源\n")
                f.write(f"# 过滤: {filter_info}\n")
                f.write(f"# 过滤数: {self.stats['filtered_count']} 个\n")
                f.write("#" + "=" * 58 + "\n")
                
                for ip_with_port in sorted(self.ipv4_data.keys()):
                    comment = self.ipv4_data[ip_with_port]
                    f.write(f"{ip_with_port}#{comment}\n")
            
            logger.info(f"✅ IPv4已保存: {ipv4_path} ({len(self.ipv4_data)} 个)")
        except Exception as e:
            logger.error(f"保存IPv4失败: {e}")
        
        # 保存IPv6
        ipv6_path = os.path.join(output_dir, 'ipv6.txt')
        try:
            with open(ipv6_path, 'w', encoding='utf-8') as f:
                f.write(f"ipv6.list.updated.at#Upd{timestamp}\n")
                f.write(f"# 总数: {len(self.ipv6_data)} 个IP\n")
                f.write(f"# 来源: {self.stats['success_sources']} 个数据源\n")
                f.write(f"# 过滤: {filter_info}\n")
                f.write("#" + "=" * 58 + "\n")
                
                for ip_with_port in sorted(self.ipv6_data.keys()):
                    comment = self.ipv6_data[ip_with_port]
                    f.write(f"{ip_with_port}#{comment}\n")
            
            logger.info(f"✅ IPv6已保存: {ipv6_path} ({len(self.ipv6_data)} 个)")
        except Exception as e:
            logger.error(f"保存IPv6失败: {e}")
        
        # 保存统计信息
        stats_path = os.path.join(output_dir, f'stats_{timestamp}.json')
        try:
            with open(stats_path, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, ensure_ascii=False)
            logger.info(f"✅ 统计信息已保存: {stats_path}")
        except Exception as e:
            logger.error(f"保存统计信息失败: {e}")
    
    def print_statistics(self):
        """打印统计信息"""
        logger.info("=" * 60)
        logger.info("📊 收集完成 - 统计信息")
        logger.info("=" * 60)
        logger.info(f"📁 总数据源: {self.stats['total_sources']}")
        logger.info(f"✅ 成功: {self.stats['success_sources']}")
        logger.info(f"❌ 失败: {self.stats['failed_sources']}")
        logger.info(f"🌐 IPv4地址: {self.stats['ipv4_count']}")
        logger.info(f"🌐 IPv6地址: {self.stats['ipv6_count']}")
        logger.info(f"🚫 已过滤: {self.stats['filtered_count']}")
        
        if self.exclude_countries:
            logger.info(f"🚫 排除国家: {', '.join(self.exclude_countries)}")
        if self.include_countries:
            logger.info(f"✅ 包含国家: {', '.join(self.include_countries)}")
        
        if self.stats['errors']:
            logger.warning(f"⚠️ 错误列表 ({len(self.stats['errors'])} 条):")
            for error in self.stats['errors'][:5]:  # 只显示前5条
                logger.warning(f"  - {error}")
        logger.info("=" * 60)


def main():
    """主函数"""
    try:
        # ========== 在这里配置过滤选项 ==========
        
        # 方式1: 排除美国，保留其他所有国家
        collector = CloudflareIPCollector(
            port='8443',
            include_countries=['US'],  # 🚫 排除美国
            timeout=15,
            max_retries=3
        )
        
        # 方式2: 只保留中国、香港、新加坡
        # collector = CloudflareIPCollector(
        #     port='8443',
        #     include_countries=['CN', 'HK', 'SG'],  # ✅ 只包含这些国家
        #     timeout=15,
        #     max_retries=3
        # )
        
        # 方式3: 排除多个国家
        # collector = CloudflareIPCollector(
        #     port='8443',
        #     exclude_countries=['US', 'JP', 'KR', 'DE'],  # 排除美国、日本、韩国、德国
        #     timeout=15,
        #     max_retries=3
        # )
        
        # 方式4: 只包含中国，并排除美国（排除优先）
        # collector = CloudflareIPCollector(
        #     port='8443',
        #     exclude_countries=['US'],
        #     include_countries=['CN', 'HK', 'TW', 'SG'],
        #     timeout=15,
        #     max_retries=3
        # )
        
        # ======================================
        
        # 开始收集
        collector.collect()
        
        # 保存结果
        collector.save_results()
        
        # 打印统计
        collector.print_statistics()
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ 用户中断执行")
    except Exception as e:
        logger.error(f"❌ 程序执行失败: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
