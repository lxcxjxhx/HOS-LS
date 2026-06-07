"""威胁情报分析与趋势预测模块

基于多源数据实现威胁情报分析和漏洞趋势预测。
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

import requests
from bs4 import BeautifulSoup

from src.utils.logger import get_logger

logger = get_logger(__name__)

# 尝试导入 scikit-learn 和 numpy，如果不可用则禁用趋势预测
try:
    from sklearn.linear_model import LinearRegression
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn 未安装，趋势预测功能将被禁用")


class ThreatIntelligenceAnalyzer:
    """威胁情报分析器"""

    def __init__(self):
        self.sources = {
            "freebuf": {
                "name": "FreeBuf",
                "url": "https://www.freebuf.com/vuls",
                "parser": self._parse_freebuf
            },
            "anquanke": {
                "name": "安全客",
                "url": "https://www.anquanke.com/vul",
                "parser": self._parse_anquanke
            }
        }
        self.data_dir = "data/threat_intelligence"
        import os
        os.makedirs(self.data_dir, exist_ok=True)

    def _parse_freebuf(self, content: str) -> List[Dict[str, Any]]:
        """解析FreeBuf漏洞资讯"""
        vulnerabilities = []
        try:
            soup = BeautifulSoup(content, "html.parser")
            article_items = soup.find_all("div", class_="article-item")
            for item in article_items:
                # 提取文章信息
                title_elem = item.find("h2", class_="title")
                if not title_elem:
                    continue

                name = title_elem.text.strip()
                link = title_elem.find("a")["href"] if title_elem.find("a") else ""

                # 提取描述
                desc_elem = item.find("p", class_="desc")
                description = desc_elem.text.strip() if desc_elem else ""

                # 提取发布日期
                date_elem = item.find("span", class_="time")
                published_date_str = date_elem.text.strip() if date_elem else ""
                published_date = None
                try:
                    if published_date_str:
                        published_date = datetime.strptime(published_date_str, "%Y-%m-%d")
                except Exception:
                    pass

                # 提取漏洞类型和严重程度（如果有）
                tags = []
                tag_elems = item.find_all("span", class_="tag")
                for tag_elem in tag_elems:
                    tags.append(tag_elem.text.strip())

                vulnerabilities.append({
                    "title": name,
                    "url": link,
                    "description": description,
                    "published_date": published_date,
                    "tags": tags,
                    "source": "FreeBuf"
                })
        except Exception as e:
            logger.error(f"解析FreeBuf失败: {e}")
        return vulnerabilities

    def _parse_anquanke(self, content: str) -> List[Dict[str, Any]]:
        """解析安全客漏洞资讯"""
        vulnerabilities = []
        try:
            soup = BeautifulSoup(content, "html.parser")
            article_items = soup.find_all("article", class_="post-item")
            for item in article_items:
                # 提取文章信息
                title_elem = item.find("h2", class_="post-title")
                if not title_elem:
                    continue

                name = title_elem.text.strip()
                link = title_elem.find("a")["href"] if title_elem.find("a") else ""

                # 提取描述
                desc_elem = item.find("p", class_="post-content")
                description = desc_elem.text.strip() if desc_elem else ""

                # 提取发布日期
                date_elem = item.find("time", class_="post-time")
                published_date_str = date_elem.text.strip() if date_elem else ""
                published_date = None
                try:
                    if published_date_str:
                        published_date = datetime.strptime(published_date_str, "%Y-%m-%d")
                except Exception:
                    pass

                # 提取漏洞类型和严重程度（如果有）
                tags = []
                tag_elems = item.find_all("span", class_="tag")
                for tag_elem in tag_elems:
                    tags.append(tag_elem.text.strip())

                vulnerabilities.append({
                    "title": name,
                    "url": link,
                    "description": description,
                    "published_date": published_date,
                    "tags": tags,
                    "source": "安全客"
                })
        except Exception as e:
            logger.error(f"解析安全客失败: {e}")
        return vulnerabilities

    def fetch_threat_intelligence(self, days: int = 30) -> List[Dict[str, Any]]:
        """获取威胁情报

        Args:
            days: 最近多少天的情报

        Returns:
            威胁情报列表
        """
        all_intelligence = []
        cutoff_date = datetime.now() - timedelta(days=days)

        for source_name, source_config in self.sources.items():
            logger.info(f"从 {source_config['name']} 获取威胁情报")
            try:
                response = requests.get(source_config['url'], timeout=30, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                response.raise_for_status()
                intelligence = source_config['parser'](response.content)
                
                # 过滤时间范围内的情报
                filtered_intelligence = []
                for item in intelligence:
                    if item.get('published_date') and item['published_date'] >= cutoff_date:
                        filtered_intelligence.append(item)
                
                all_intelligence.extend(filtered_intelligence)
                logger.info(f"从 {source_config['name']} 获取了 {len(filtered_intelligence)} 条情报")
            except Exception as e:
                logger.error(f"从 {source_config['name']} 获取情报失败: {e}")
            
            # 控制请求频率
            time.sleep(2)

        # 按发布日期排序
        all_intelligence.sort(key=lambda x: x.get('published_date', datetime.min), reverse=True)
        return all_intelligence

    def analyze_trends(self, intelligence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析漏洞趋势

        Args:
            intelligence: 威胁情报列表

        Returns:
            趋势分析结果
        """
        if not intelligence:
            return {}

        # 按日期分组
        date_groups = {}
        for item in intelligence:
            date = item.get('published_date')
            if date:
                date_str = date.strftime('%Y-%m-%d')
                if date_str not in date_groups:
                    date_groups[date_str] = []
                date_groups[date_str].append(item)

        # 计算每日漏洞数量
        daily_counts = []
        dates = []
        for date_str, items in sorted(date_groups.items()):
            dates.append(date_str)
            daily_counts.append(len(items))

        # 预测未来趋势
        prediction = self._predict_trend(daily_counts)

        # 分析热门漏洞类型
        tag_counts = {}
        for item in intelligence:
            for tag in item.get('tags', []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        # 按来源分析
        source_counts = {}
        for item in intelligence:
            source = item.get('source', 'Unknown')
            source_counts[source] = source_counts.get(source, 0) + 1

        return {
            "daily_counts": dict(zip(dates, daily_counts)),
            "prediction": prediction,
            "top_tags": dict(sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "source_distribution": source_counts,
            "total_intelligence": len(intelligence)
        }

    def _predict_trend(self, counts: List[int]) -> List[int]:
        """预测未来趋势

        Args:
            counts: 历史数据

        Returns:
            预测结果
        """
        if not SKLEARN_AVAILABLE:
            return []

        if len(counts) < 3:
            return []

        try:
            # 准备数据
            import numpy as np
            from sklearn.linear_model import LinearRegression
            X = np.array(range(len(counts))).reshape(-1, 1)
            y = np.array(counts)

            # 训练模型
            model = LinearRegression()
            model.fit(X, y)

            # 预测未来7天
            future_X = np.array(range(len(counts), len(counts) + 7)).reshape(-1, 1)
            predictions = model.predict(future_X)

            # 转换为整数
            predictions = [max(0, int(round(p))) for p in predictions]
            return predictions
        except Exception as e:
            logger.error(f"预测趋势失败: {e}")
            return []

    def generate_threat_report(self, intelligence: List[Dict[str, Any]], trends: Dict[str, Any]) -> Dict[str, Any]:
        """生成威胁情报报告

        Args:
            intelligence: 威胁情报列表
            trends: 趋势分析结果

        Returns:
            威胁情报报告
        """
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_intelligence": trends.get("total_intelligence", 0),
                "sources": list(trends.get("source_distribution", {}).keys()),
                "top_tags": list(trends.get("top_tags", {}).keys())[:5]
            },
            "trends": {
                "daily_counts": trends.get("daily_counts", {}),
                "prediction": trends.get("prediction", []),
                "top_tags": trends.get("top_tags", {})
            },
            "recent_intelligence": intelligence[:10],  # 最近10条情报
            "recommendations": self._generate_recommendations(intelligence, trends)
        }
        return report

    def _generate_recommendations(self, intelligence: List[Dict[str, Any]], trends: Dict[str, Any]) -> List[str]:
        """生成安全建议

        Args:
            intelligence: 威胁情报列表
            trends: 趋势分析结果

        Returns:
            安全建议列表
        """
        recommendations = []

        # 基于热门标签生成建议
        top_tags = trends.get("top_tags", {})
        if top_tags:
            recommendations.append(f"关注热门漏洞类型: {', '.join(list(top_tags.keys())[:3])}")

        # 基于趋势生成建议
        daily_counts = trends.get("daily_counts", {})
        if daily_counts:
            recent_days = list(daily_counts.keys())[-7:]
            recent_counts = [daily_counts[day] for day in recent_days]
            avg_recent = sum(recent_counts) / len(recent_counts)
            if avg_recent > 5:
                recommendations.append("近期漏洞数量较多，建议加强安全监控")

        # 基于情报内容生成建议
        for item in intelligence[:5]:
            if "高危" in item.get("tags", []) or "严重" in item.get("tags", []):
                recommendations.append(f"关注高危漏洞: {item.get('title', '')}")

        return recommendations

    def save_intelligence(self, intelligence: List[Dict[str, Any]], filename: str = "threat_intelligence.json"):
        """保存威胁情报到文件

        Args:
            intelligence: 威胁情报列表
            filename: 文件名
        """
        import os
        file_path = os.path.join(self.data_dir, filename)
        # 转换日期为字符串
        for item in intelligence:
            if isinstance(item.get('published_date'), datetime):
                item['published_date'] = item['published_date'].isoformat()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(intelligence, f, indent=2, ensure_ascii=False)
        logger.info(f"威胁情报已保存到 {file_path}")

    def load_intelligence(self, filename: str = "threat_intelligence.json") -> List[Dict[str, Any]]:
        """从文件加载威胁情报

        Args:
            filename: 文件名

        Returns:
            威胁情报列表
        """
        import os
        file_path = os.path.join(self.data_dir, filename)
        intelligence = []
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # 转换日期字符串为datetime对象
                for item in data:
                    if isinstance(item.get('published_date'), str):
                        try:
                            item['published_date'] = datetime.fromisoformat(item['published_date'])
                        except Exception:
                            pass
                intelligence = data
                logger.info(f"从 {file_path} 加载了 {len(intelligence)} 条威胁情报")
            except Exception as e:
                logger.error(f"加载威胁情报失败: {e}")
        return intelligence

    def run_analysis(self, days: int = 30) -> Dict[str, Any]:
        """运行威胁情报分析

        Args:
            days: 分析最近多少天的情报

        Returns:
            分析报告
        """
        logger.info(f"开始分析最近 {days} 天的威胁情报")
        
        # 获取威胁情报
        intelligence = self.fetch_threat_intelligence(days)
        
        # 保存情报
        self.save_intelligence(intelligence)
        
        # 分析趋势
        trends = self.analyze_trends(intelligence)
        
        # 生成报告
        report = self.generate_threat_report(intelligence, trends)
        
        # 保存报告
        import os
        report_path = os.path.join(self.data_dir, f"threat_report_{datetime.now().strftime('%Y%m%d')}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"威胁情报报告已保存到 {report_path}")
        
        return report


# 测试代码
if __name__ == "__main__":
    analyzer = ThreatIntelligenceAnalyzer()
    report = analyzer.run_analysis(days=7)
    print(f"分析完成，生成了包含 {report['summary']['total_intelligence']} 条情报的报告")
    print(f"热门漏洞类型: {', '.join(report['summary']['top_tags'])}")
    print(f"安全建议: {', '.join(report['recommendations'])}")
