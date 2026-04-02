# Test Case ID: GL-P01
# Rule: ai_security.gradient_leakage
# Test Type: positive
# Description: 梯度泄露风险
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

import torch
import torch.nn as nn

class FederatedLearning:
    def __init__(self, model):
        self.model = model
        
    def compute_gradient(self, input_data, labels):
        """计算梯度 - 可能泄露隐私"""
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.SGD(self.model.parameters(), lr=0.01)
        
        outputs = self.model(input_data)
        loss = criterion(outputs, labels)
        
        # 反向传播计算梯度
        loss.backward()
        
        # 返回完整梯度（可能泄露输入数据信息）
        gradients = []
        for param in self.model.parameters():
            gradients.append(param.grad.clone())
            
        return gradients  # 攻击者可能从梯度重构输入数据
        
    def share_gradients(self, gradients):
        """共享梯度到中央服务器"""
        # 在联邦学习中，梯度被共享
        # 但可能泄露本地数据隐私
        server.receive_gradients(gradients)
