"""context_builder.py 单元测试

验证数据流追踪功能：
1. 上下文构建正常
2. 数据流追踪功能
3. 跨文件关联分析
"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.ai.pure_ai.context_builder import ContextBuilder


def test_build_java_context():
    """测试 Java 文件上下文构建"""
    java_content = """
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @GetMapping("/users")
    public User getUser(@RequestParam String id) {
        return userRepository.findById(id);
    }
    
    @GetMapping("/users/search")
    public List<User> searchUsers(@RequestParam String name) {
        return userRepository.findByName(name);
    }
}
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
        f.write(java_content)
        temp_path = f.name
    
    try:
        builder = ContextBuilder()
        context = builder.build_context(temp_path)
        
        assert context['file_type'] == 'java'
        assert 'spring_mappings' in context
        assert 'class_structure' in context
        assert 'security_relevant' in context
        assert 'imports' in context
        assert 'function_calls' in context
        assert 'data_flow' in context
        
        assert len(context['spring_mappings']) > 0, "应该检测到Spring映射"
        assert len(context['imports']) > 0, "应该检测到导入语句"
        
        data_flow = context['data_flow']
        assert 'entry_points' in data_flow
        assert 'service_calls' in data_flow
        assert 'data_access' in data_flow
        assert 'flow_paths' in data_flow
        
        print(f"[DEBUG] 检测到 {len(context['spring_mappings'])} 个Spring映射")
        print(f"[DEBUG] 检测到 {len(data_flow['entry_points'])} 个入口点")
        print("[PASS] test_build_java_context")
    finally:
        os.unlink(temp_path)


def test_build_python_context():
    """测试 Python 文件上下文构建"""
    python_content = """
from flask import Flask, request, jsonify
from services.user_service import UserService

app = Flask(__name__)
user_service = UserService()

@app.route('/api/users', methods=['GET'])
def get_users():
    user_id = request.args.get('id')
    users = user_service.get_user(user_id)
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    result = user_service.create_user(data)
    return jsonify(result)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(python_content)
        temp_path = f.name
    
    try:
        builder = ContextBuilder()
        context = builder.build_context(temp_path)
        
        assert context['file_type'] == 'python'
        assert 'imports' in context
        assert 'function_calls' in context
        assert 'file_structure' in context
        assert 'data_flow' in context
        
        assert len(context['imports']) > 0, "应该检测到导入语句"
        assert len(context['function_calls']) > 0, "应该检测到函数调用"
        
        data_flow = context['data_flow']
        assert 'entry_points' in data_flow
        assert 'service_calls' in data_flow
        assert 'flow_paths' in data_flow
        
        print(f"[DEBUG] 检测到 {len(context['imports'])} 个导入语句")
        print(f"[DEBUG] 检测到 {len(context['function_calls'])} 个函数调用")
        print(f"[DEBUG] 检测到 {len(data_flow['entry_points'])} 个入口点")
        print("[PASS] test_build_python_context")
    finally:
        os.unlink(temp_path)


def test_data_flow_tracking_java():
    """测试 Java 数据流追踪"""
    java_content = """
@RestController
@RequestMapping("/api")
public class OrderController {
    
    @Autowired
    private OrderService orderService;
    
    @Autowired
    private OrderMapper orderMapper;
    
    @PostMapping("/orders")
    public Order createOrder(@RequestBody OrderRequest request) {
        Order order = orderService.createOrder(request);
        return order;
    }
    
    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderMapper.selectById(id);
    }
}
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
        f.write(java_content)
        temp_path = f.name
    
    try:
        builder = ContextBuilder()
        context = builder.build_context(temp_path)
        
        data_flow = context['data_flow']
        
        assert len(data_flow['entry_points']) >= 2, f"应该检测到至少2个入口点，实际 {len(data_flow['entry_points'])}"
        
        entry_methods = [e['method'] for e in data_flow['entry_points']]
        assert 'createOrder' in entry_methods, "应该检测到 createOrder 方法"
        assert 'getOrder' in entry_methods, "应该检测到 getOrder 方法"
        
        service_calls = data_flow['service_calls']
        assert len(service_calls) > 0, "应该检测到服务调用"
        
        data_access = data_flow['data_access']
        assert len(data_access) > 0, "应该检测到数据访问"
        
        print(f"[DEBUG] 入口点: {[e['method'] for e in data_flow['entry_points']]}")
        print(f"[DEBUG] 服务调用: {len(service_calls)} 个")
        print(f"[DEBUG] 数据访问: {len(data_access)} 个")
        print("[PASS] test_data_flow_tracking_java")
    finally:
        os.unlink(temp_path)


def test_data_flow_tracking_python():
    """测试 Python 数据流追踪"""
    python_content = """
from flask import Flask, request
from services.order_service import OrderService
from mappers.order_mapper import OrderMapper

app = Flask(__name__)
order_service = OrderService()
order_mapper = OrderMapper()

@app.route('/orders', methods=['POST'])
def create_order():
    data = request.json
    order = order_service.create(data)
    return order

@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    order = order_mapper.find_by_id(order_id)
    return order
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(python_content)
        temp_path = f.name
    
    try:
        builder = ContextBuilder()
        context = builder.build_context(temp_path)
        
        data_flow = context['data_flow']
        
        assert len(data_flow['entry_points']) >= 2, f"应该检测到至少2个入口点"
        
        service_calls = data_flow['service_calls']
        data_access = data_flow['data_access']
        
        print(f"[DEBUG] Python 入口点: {len(data_flow['entry_points'])} 个")
        print(f"[DEBUG] Python 服务调用: {len(service_calls)} 个")
        print(f"[DEBUG] Python 数据访问: {len(data_access)} 个")
        print("[PASS] test_data_flow_tracking_python")
    finally:
        os.unlink(temp_path)


def test_config_file_context():
    """测试配置文件上下文构建"""
    xml_content = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mapper.UserMapper">
    <select id="findUserById" resultType="User">
        SELECT * FROM users WHERE id = ${id}
    </select>
    <select id="findUsers" resultType="User">
        SELECT * FROM users WHERE name = #{name}
    </select>
</mapper>
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False, encoding='utf-8') as f:
        f.write(xml_content)
        temp_path = f.name
    
    try:
        builder = ContextBuilder()
        context = builder.build_context(temp_path)
        
        assert context['file_type'] == 'config'
        assert 'security_findings' in context
        
        findings = context['security_findings']
        assert len(findings) > 0, "应该检测到安全发现"
        
        sql_injection_findings = [f for f in findings if f.get('type') == 'SQL_INJECTION']
        assert len(sql_injection_findings) > 0, "应该检测到SQL注入"
        
        print(f"[DEBUG] 检测到 {len(findings)} 个安全发现")
        print(f"[DEBUG] SQL注入发现: {len(sql_injection_findings)} 个")
        print("[PASS] test_config_file_context")
    finally:
        os.unlink(temp_path)


def test_imports_extraction():
    """测试导入语句提取"""
    python_content = """
import os
import sys
from pathlib import Path
from typing import List, Dict
from flask import Flask, request
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(python_content)
        temp_path = f.name
    
    try:
        builder = ContextBuilder()
        imports = builder._extract_imports(temp_path)
        
        assert len(imports) >= 5, f"应该提取至少5个导入语句，实际 {len(imports)}"
        
        print(f"[DEBUG] 提取的导入语句: {imports}")
        print("[PASS] test_imports_extraction")
    finally:
        os.unlink(temp_path)


if __name__ == "__main__":
    test_build_java_context()
    test_build_python_context()
    test_data_flow_tracking_java()
    test_data_flow_tracking_python()
    test_config_file_context()
    test_imports_extraction()
    print("\n[INFO] 所有 context_builder 测试通过！")
