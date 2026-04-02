# Test Case ID: TDP-N01
# Rule: ai_security.training_data_poisoning
# Test Type: negative
# Description: 防止训练数据投毒
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import hashlib

def verify_data_integrity(data_path, expected_hash):
    """验证数据完整性"""
    with open(data_path, 'rb') as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()
    
    if data_hash != expected_hash:
        raise ValueError("数据完整性验证失败")
    return True

def detect_outliers(data, threshold=3):
    """检测异常数据点"""
    from scipy import stats
    
    z_scores = np.abs(stats.zscore(data.select_dtypes(include=[np.number])))
    outliers = (z_scores > threshold).any(axis=1)
    
    return outliers

def clean_dataset(data):
    """清洗数据集"""
    # 1. 移除异常值
    outlier_mask = detect_outliers(data)
    clean_data = data[~outlier_mask]
    
    # 2. 检查标签分布
    label_dist = clean_data['label'].value_counts(normalize=True)
    if (label_dist < 0.01).any():
        raise ValueError("检测到可能的投毒：标签分布异常")
    
    # 3. 验证数据特征
    verify_feature_ranges(clean_data)
    
    return clean_data

def verify_feature_ranges(data):
    """验证特征值范围"""
    for col in data.select_dtypes(include=[np.number]).columns:
        if data[col].min() < -1e6 or data[col].max() > 1e6:
            raise ValueError(f"特征 {col} 的值范围异常")
