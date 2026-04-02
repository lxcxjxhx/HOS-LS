# Test Case ID: GL-N01
# Rule: ai_security.gradient_leakage
# Test Type: negative
# Description: 防止梯度泄露
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import torch
import torch.nn as nn
import numpy as np

class SecureFederatedLearning:
    def __init__(self, model, noise_scale=0.01):
        self.model = model
        self.noise_scale = noise_scale
        
    def compute_gradient_with_dp(self, input_data, labels):
        """计算带差分隐私的梯度"""
        criterion = nn.CrossEntropyLoss()
        
        outputs = self.model(input_data)
        loss = criterion(outputs, labels)
        
        loss.backward()
        
        # 添加噪声实现差分隐私
        noisy_gradients = []
        for param in self.model.parameters():
            if param.grad is not None:
                noise = torch.normal(
                    0, 
                    self.noise_scale, 
                    param.grad.shape
                )
                noisy_grad = param.grad.clone() + noise
                noisy_gradients.append(noisy_grad)
                
        return noisy_gradients
        
    def clip_gradient(self, gradients, max_norm=1.0):
        """梯度裁剪，限制信息泄露"""
        total_norm = torch.norm(
            torch.stack([torch.norm(g) for g in gradients])
        )
        clip_coef = max_norm / (total_norm + 1e-6)
        
        if clip_coef < 1:
            return [g * clip_coef for g in gradients]
        return gradients
