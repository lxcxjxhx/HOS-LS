from crewai import Agent, Task, Crew
from typing import Dict, Any, Optional
from src.core.rag_graph_integrator import get_rag_graph_integrator
from src.db.neo4j_connection import Neo4jManager
from src.ai.dspy_optimization import get_dspy_programs


class HOSLSCrewAI:
    """HOS-LS CrewAI角色团队"""
    
    def __init__(self):
        """初始化CrewAI团队"""
        self.rag_integrator = get_rag_graph_integrator()
        self.neo4j_manager = Neo4jManager({})
        self.dspy_programs = get_dspy_programs()
    
    def create_retrieval_agent(self) -> Agent:
        """创建检索Agent"""
        return Agent(
            role="漏洞检索专家",
            goal="根据代码分析检索最相关的CVE漏洞信息",
            backstory="你是一位专注于软件安全的漏洞检索专家，擅长从大量CVE数据中快速找到与目标代码相关的漏洞信息。你使用混合检索技术，结合向量搜索和图数据库查询，确保找到最相关的漏洞。",
            verbose=True
        )
    
    def create_graph_agent(self) -> Agent:
        """创建图分析Agent"""
        return Agent(
            role="攻击链分析专家",
            goal="基于检索到的CVE构建攻击链和漏洞关联图",
            backstory="你是一位网络安全专家，擅长分析漏洞之间的关联关系，构建攻击链，并识别潜在的攻击路径。你使用图数据库技术来可视化和分析漏洞之间的复杂关系。",
            verbose=True
        )
    
    def create_reasoning_agent(self) -> Agent:
        """创建推理Agent"""
        return Agent(
            role="漏洞分析专家",
            goal="深入分析代码中的漏洞，评估其严重性和影响范围",
            backstory="你是一位资深的安全分析师，擅长深入分析漏洞的根本原因、利用方式和潜在影响。你结合检索到的CVE信息和攻击链分析，提供全面的漏洞分析报告。",
            verbose=True
        )
    
    def create_critic_agent(self) -> Agent:
        """创建评估Agent"""
        return Agent(
            role="质量评估专家",
            goal="评估漏洞分析的质量，确保分析结果准确、全面",
            backstory="你是一位严谨的质量评估专家，擅长评估漏洞分析的质量和完整性。你会仔细检查分析结果，确保没有遗漏重要信息，并提供改进建议。",
            verbose=True
        )
    
    def create_repair_agent(self) -> Agent:
        """创建修复Agent"""
        return Agent(
            role="漏洞修复专家",
            goal="为识别出的漏洞提供具体的修复建议和代码示例",
            backstory="你是一位经验丰富的安全修复专家，擅长为各种类型的漏洞提供有效的修复方案。你不仅提供修复建议，还会生成具体的代码示例，帮助开发人员快速实施修复。",
            verbose=True
        )
    
    def create_tasks(self, input_code: str) -> list[Task]:
        """创建任务列表"""
        retrieval_agent = self.create_retrieval_agent()
        graph_agent = self.create_graph_agent()
        reasoning_agent = self.create_reasoning_agent()
        critic_agent = self.create_critic_agent()
        repair_agent = self.create_repair_agent()
        
        # 任务1：检索相关CVE
        task1 = Task(
            description=f"分析以下代码并检索最相关的CVE漏洞信息：\n{input_code}",
            expected_output="返回最相关的10个CVE漏洞信息，包括CVE ID、描述、严重程度和相关代码模式",
            agent=retrieval_agent
        )
        
        # 任务2：构建攻击链
        task2 = Task(
            description="基于检索到的CVE信息，构建可能的攻击链和漏洞关联图",
            expected_output="返回构建的攻击链信息，包括漏洞之间的关联关系和潜在的攻击路径",
            agent=graph_agent,
            context=[task1]
        )
        
        # 任务3：深入分析漏洞
        task3 = Task(
            description="基于检索结果和攻击链分析，深入分析代码中的漏洞",
            expected_output="返回详细的漏洞分析报告，包括漏洞类型、严重程度、影响范围和利用方式",
            agent=reasoning_agent,
            context=[task1, task2]
        )
        
        # 任务4：评估分析质量
        task4 = Task(
            description="评估漏洞分析的质量，确保分析结果准确、全面",
            expected_output="返回质量评估结果和改进建议",
            agent=critic_agent,
            context=[task3]
        )
        
        # 任务5：生成修复建议
        task5 = Task(
            description="基于漏洞分析结果，生成具体的修复建议和代码示例",
            expected_output="返回详细的修复建议，包括具体的代码修改方案和修复注意事项",
            agent=repair_agent,
            context=[task3, task4]
        )
        
        return [task1, task2, task3, task4, task5]
    
    def run_crew(self, input_code: str) -> Dict[str, Any]:
        """运行CrewAI团队"""
        tasks = self.create_tasks(input_code)
        
        crew = Crew(
            agents=[
                self.create_retrieval_agent(),
                self.create_graph_agent(),
                self.create_reasoning_agent(),
                self.create_critic_agent(),
                self.create_repair_agent()
            ],
            tasks=tasks,
            verbose=2
        )
        
        result = crew.kickoff()
        
        # 处理结果
        return {
            "crew_result": result,
            "tasks": [task.description for task in tasks]
        }


def get_crewai_team() -> HOSLSCrewAI:
    """获取CrewAI团队实例"""
    return HOSLSCrewAI()
