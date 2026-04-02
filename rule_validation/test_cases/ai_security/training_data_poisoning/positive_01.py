# Test Case ID: TDP-P01
# Rule: ai_security.training_data_poisoning
# Test Type: positive
# Description: 训练数据投毒风险
# Expected Detection: true
# Expected Severity: CRITICAL
# Code Type: vulnerable

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

def load_training_data(source_path):
    """加载训练数据 - 没有验证"""
    # 直接从外部源加载数据
    data = pd.read_csv(source_path)
    return data

def prepare_dataset(data):
    """准备数据集 - 没有异常检测"""
    X = data.drop('label', axis=1)
    y = data['label']
    
    # 没有检查数据分布
    # 没有检测异常样本
    # 没有验证数据来源
    
    return train_test_split(X, y, test_size=0.2)

# 攻击者可以在训练数据中注入恶意样本
# 例如：添加带有错误标签的样本
