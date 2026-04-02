import os
import json
from typing import List, Dict, Any, Optional
from langchain_openai import OpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableSequence
from .context_builder import ContextBuilder

class AISemanticEngine:
    def __init__(self, api_key: Optional[str] = None):
        """
        初始化AI语义分析引擎
        
        Args:
            api_key: OpenAI API密钥，如果不提供则使用环境变量中的OPENAI_API_KEY
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key is required")
        
        self.llm = OpenAI(api_key=self.api_key, temperature=0.3)
        self.context_builder = ContextBuilder()
        self._setup_prompts()
    
    def _setup_prompts(self):
        """
        设置分析Prompt
        """
        # 漏洞分析Prompt
        self.vulnerability_prompt = PromptTemplate(
            input_variables=["code_context", "vulnerability_type"],
            template="""你是高级安全审计专家，请分析以下代码是否存在{vulnerability_type}漏洞：

代码：
{code_context}

请输出：
1. 是否存在漏洞（是/否）
2. 漏洞类型
3. 攻击路径
4. 可利用方式
5. 修复建议

输出格式：JSON
{"vulnerable": bool, "type": string, "attack_path": string, "exploit": string, "fix": string}"""
        )
        
        # 代码安全分析Prompt
        self.code_security_prompt = PromptTemplate(
            input_variables=["code_context"],
            template="""你是高级安全审计专家，请分析以下代码的安全性：

代码：
{code_context}

请识别：
1. 所有可能的安全漏洞
2. 每个漏洞的类型和严重程度
3. 攻击路径和可利用方式
4. 修复建议

输出格式：JSON
{"vulnerabilities": [{"type": string, "severity": string, "attack_path": string, "exploit": string, "fix": string}]}"""
        )
        
        # 攻击链分析Prompt
        self.attack_chain_prompt = PromptTemplate(
            input_variables=["code_context", "entry_points", "danger_calls"],
            template="""你是高级安全审计专家，请分析以下代码的攻击链：

代码：
{code_context}

入口点：
{entry_points}

危险调用：
{danger_calls}

请输出：
1. 可能的攻击链
2. 每个攻击链的风险等级
3. 攻击步骤

输出格式：JSON
{"attack_chains": [{"chain": [string], "risk": string, "steps": [string]}]}"""
        )
    
    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """
        分析代码文件
        
        Args:
            files: 要分析的文件列表
            
        Returns:
            分析结果
        """
        # 构建上下文
        context = self.context_builder.build(files)
        
        # 分层分析
        function_level_results = self._analyze_function_level(files)
        file_level_results = self._analyze_file_level(files)
        project_level_results = self._analyze_project_level(files, context)
        
        return {
            "context": context,
            "function_level": function_level_results,
            "file_level": file_level_results,
            "project_level": project_level_results
        }
    
    def _analyze_function_level(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        函数级分析
        """
        results = []
        for file_path in files:
            if file_path.endswith('.py'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 简单的函数提取，实际项目中可以使用AST更精确地提取函数
                    functions = self._extract_functions(content)
                    for func_name, func_code in functions.items():
                        # 风险驱动分析：只分析包含危险模式的函数
                        if self._has_danger_patterns(func_code):
                            analysis = self._analyze_function(func_code, func_name, file_path)
                            results.append(analysis)
                except Exception as e:
                    print(f"Error analyzing function level in {file_path}: {e}")
        return results
    
    def _analyze_file_level(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        文件级分析
        """
        results = []
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 风险驱动分析：只分析包含危险模式的文件
                if self._has_danger_patterns(content):
                    analysis = self._analyze_file(content, file_path)
                    results.append(analysis)
            except Exception as e:
                print(f"Error analyzing file level in {file_path}: {e}")
        return results
    
    def _analyze_project_level(self, files: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        项目级分析
        """
        try:
            # 构建项目级上下文
            project_context = {
                "entry_points": context.get("entry_points", []),
                "danger_calls": context.get("danger_calls", []),
                "data_flow": context.get("data_flow", [])
            }
            
            # 分析攻击链
            attack_chain_analysis = self._analyze_attack_chains(project_context)
            
            return {
                "attack_chains": attack_chain_analysis,
                "overall_risk": self._calculate_overall_risk(attack_chain_analysis)
            }
        except Exception as e:
            print(f"Error analyzing project level: {e}")
            return {"error": str(e)}
    
    def _extract_functions(self, content: str) -> Dict[str, str]:
        """
        提取Python文件中的函数
        """
        import ast
        try:
            tree = ast.parse(content)
            functions = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 提取函数代码
                    start_line = node.lineno - 1
                    end_line = node.end_lineno
                    lines = content.split('\n')
                    func_code = '\n'.join(lines[start_line:end_line])
                    functions[node.name] = func_code
            return functions
        except Exception:
            return {}
    
    def _has_danger_patterns(self, code: str) -> bool:
        """
        检查代码是否包含危险模式
        """
        danger_patterns = [
            'exec(', 'eval(', 'input(', 'open(',
            'cursor.execute', 'db.execute', 'conn.execute',
            'os.system', 'subprocess', 'shell=True'
        ]
        
        for pattern in danger_patterns:
            if pattern in code:
                return True
        return False
    
    def _analyze_function(self, func_code: str, func_name: str, file_path: str) -> Dict[str, Any]:
        """
        分析单个函数
        """
        try:
            # 使用RunnableSequence替代LLMChain
            chain = RunnableSequence(
                self.code_security_prompt,
                self.llm,
                StrOutputParser()
            )
            result = chain.invoke({"code_context": func_code})
            
            # 解析JSON结果
            try:
                analysis = json.loads(result)
            except json.JSONDecodeError:
                analysis = {"vulnerabilities": []}
            
            return {
                "function": func_name,
                "file": file_path,
                "analysis": analysis
            }
        except Exception as e:
            return {
                "function": func_name,
                "file": file_path,
                "error": str(e)
            }
    
    def _analyze_file(self, content: str, file_path: str) -> Dict[str, Any]:
        """
        分析单个文件
        """
        try:
            # 使用RunnableSequence替代LLMChain
            chain = RunnableSequence(
                self.code_security_prompt,
                self.llm,
                StrOutputParser()
            )
            result = chain.invoke({"code_context": content})
            
            # 解析JSON结果
            try:
                analysis = json.loads(result)
            except json.JSONDecodeError:
                analysis = {"vulnerabilities": []}
            
            return {
                "file": file_path,
                "analysis": analysis
            }
        except Exception as e:
            return {
                "file": file_path,
                "error": str(e)
            }
    
    def _analyze_attack_chains(self, project_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        分析攻击链
        """
        try:
            entry_points_str = json.dumps(project_context.get("entry_points", []), ensure_ascii=False)
            danger_calls_str = json.dumps(project_context.get("danger_calls", []), ensure_ascii=False)
            
            # 使用RunnableSequence替代LLMChain
            chain = RunnableSequence(
                self.attack_chain_prompt,
                self.llm,
                StrOutputParser()
            )
            result = chain.invoke({
                "code_context": "Project code analysis",
                "entry_points": entry_points_str,
                "danger_calls": danger_calls_str
            })
            
            # 解析JSON结果
            try:
                analysis = json.loads(result)
                return analysis.get("attack_chains", [])
            except json.JSONDecodeError:
                return []
        except Exception as e:
            print(f"Error analyzing attack chains: {e}")
            return []
    
    def _calculate_overall_risk(self, attack_chains: List[Dict[str, Any]]) -> str:
        """
        计算整体风险等级
        """
        if not attack_chains:
            return "Low"
        
        high_risk_count = sum(1 for chain in attack_chains if chain.get("risk", "").lower() == "high")
        medium_risk_count = sum(1 for chain in attack_chains if chain.get("risk", "").lower() == "medium")
        
        if high_risk_count > 0:
            return "High"
        elif medium_risk_count > 0:
            return "Medium"
        else:
            return "Low"
