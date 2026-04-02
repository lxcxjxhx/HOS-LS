# Test Case ID: TL-P01
# Rule: ai_security.training_data_leakage
# Test Type: positive
# Description: 训练数据与测试数据混合
# Expected Detection: true
# Expected Severity: HIGH
# Code Type: vulnerable

from sklearn.model_selection import train_test_split

# 错误的数据集划分方式
X = all_data
y = all_labels

# 先划分训练集和测试集
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# 但是在训练集上进行了数据增强，增强数据包含了测试集特征
X_train_augmented = augment_data(X_train)  # 可能泄露测试集信息

# 使用增强后的数据训练
model.fit(X_train_augmented, y_train)
