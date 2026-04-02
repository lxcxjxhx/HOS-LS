# Test Case ID: TL-N01
# Rule: ai_security.training_data_leakage
# Test Type: negative
# Description: 正确的数据集划分和预处理
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# 正确的数据划分
X = all_data
y = all_labels

# 先划分训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 使用训练集拟合 scaler
scaler = StandardScaler()
scaler.fit(X_train)

# 分别转换训练集和测试集
X_train_scaled = scaler.transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 训练模型
model.fit(X_train_scaled, y_train)
