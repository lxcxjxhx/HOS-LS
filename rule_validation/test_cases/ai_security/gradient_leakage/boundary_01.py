# Test Case ID: GL-B01
# Rule: ai_security.gradient_leakage
# Test Type: boundary
# Description: 本地训练不共享梯度（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import torch
import torch.nn as nn

class LocalTrainer:
    """纯本地训练，不共享梯度"""
    
    def __init__(self, model):
        self.model = model
        
    def train_locally(self, train_loader, epochs=10):
        """在本地完整训练模型"""
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.model.parameters())
        
        for epoch in range(epochs):
            for inputs, labels in train_loader:
                optimizer.zero_grad()
                outputs = self.model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
                
        # 仅共享最终模型参数，不共享中间梯度
        return self.model.state_dict()
        
    def export_model(self, path):
        """导出训练好的模型"""
        torch.save(self.model.state_dict(), path)
        # 不泄露训练过程中的梯度信息
