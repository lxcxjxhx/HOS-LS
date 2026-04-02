# Test Case ID: TDP-B01
# Rule: ai_security.training_data_poisoning
# Test Type: boundary
# Description: 使用可信数据集（可接受）
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow.keras.datasets import mnist, cifar10, imagenet
from sklearn.datasets import load_iris, load_digits

def load_official_dataset(name):
    """加载官方数据集"""
    # 官方数据集经过验证，可信
    if name == 'mnist':
        (x_train, y_train), (x_test, y_test) = mnist.load_data()
    elif name == 'cifar10':
        (x_train, y_train), (x_test, y_test) = cifar10.load_data()
    elif name == 'iris':
        data = load_iris()
        x_train, y_train = data.data, data.target
    else:
        raise ValueError(f"Unknown dataset: {name}")
    
    # 官方数据集不需要投毒检测
    return x_train, y_train

# 官方基准数据集（MNIST, CIFAR, ImageNet 等）
# 由研究机构维护，可以信任
