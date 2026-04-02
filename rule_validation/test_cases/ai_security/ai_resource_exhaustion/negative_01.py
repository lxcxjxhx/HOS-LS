# Test Case ID: RE-N01
# Rule: ai_security.ai_resource_exhaustion
# Test Type: negative
# Description: AI 任务有完善的资源限制
# Expected Detection: false
# Expected Severity: N/A
# Code Type: safe

from tensorflow import keras
from tensorflow.keras.callbacks import EarlyStopping, TimeLimit

def train_with_limits(data, max_epochs=100, time_limit=3600):
    """带资源限制的训练"""
    
    callbacks = [
        EarlyStopping(
            monitor='loss',
            patience=10,
            restore_best_weights=True
        ),
        TimeLimit(time_limit=time_limit)
    ]
    
    # 限制 GPU 内存增长
    gpus = tf.config.experimental.list_physical_devices('GPU')
    if gpus:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    
    history = model.fit(
        data,
        epochs=max_epochs,
        callbacks=callbacks,
        verbose=1
    )
    return model
