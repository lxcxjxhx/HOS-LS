# Test Case ID: MS-N01
# Rule: ai_security.insecure_model_serialization
# Test Type: negative
# Description: 使用安全的模型序列化方式
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow import keras
import hashlib

# 使用 Keras 内置的安全格式保存模型
model.save('model.h5')  # HDF5 格式
# 或
model.save('model.keras')  # Keras 新格式

# 加载时验证完整性
def load_verified_model(path, expected_hash):
    import hashlib
    with open(path, 'rb') as f:
        data = f.read()
        if hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError("模型完整性验证失败")
    return keras.models.load_model(path)
