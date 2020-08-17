import os
import time
from PIL import Image
from tqdm import tqdm
import numpy as np
import pandas as pd
import pickle

from sklearn.model_selection import train_test_split

import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.preprocessing.image import ImageDataGenerator

# 超参数

TRAIN_SIZE = 0.8
VAL_SIZE = 0.1
TEST_SIZE = 0.1
SEED = 4396

LENGTH = 512
WIDTH, HEIGHT = 32, 16
BATCH_SIZE = 16
EPOCH = 300
SHUFFLE = False
CLASSES = 2

LR = 1e-4


datapath = "/home/jovyan/histogram"

with open("/home/datacon/malware/XXX/black.txt", 'r') as f:
    black_list = f.read().strip().split()

with open("/home/datacon/malware/XXX/white.txt", 'r') as f:
    white_list = f.read().strip().split()

black_path = [os.path.join(datapath, sp) for sp in black_list]
white_path = [os.path.join(datapath, sp) for sp in white_list]

raw_feature, raw_labels = [], []

with tqdm(total=11647, ncols=80, desc="histogram") as pbar:
    for fp in black_path:
        with open(fp+'.txt', 'r') as f:
            feature = f.readlines()
        feature = [float(his.strip()) for his in feature]
        raw_feature.append(feature)
        raw_labels.append(1)
        pbar.update(1)
    for fp in white_path:
        with open(fp+'.txt', 'r') as f:
            feature = f.readlines()
        feature = [float(his.strip()) for his in feature]
        raw_feature.append(feature)
        raw_labels.append(0)
        pbar.update(1)

# 打乱顺序

np.random.seed(SEED)
tf.random.set_seed(SEED)

features, labels = np.array(raw_feature, dtype=np.float32), np.array(raw_labels, dtype=np.int32)

index = list(range(len(labels)))
np.random.shuffle(index)

features = features[index]
labels = labels[index] 

# 划分数据集

train_features, test_features, train_label, test_label = train_test_split(
    features,
    labels,
    test_size=TEST_SIZE,
    stratify=labels,
    random_state=SEED)
train_features, valid_features, train_label, valid_label = train_test_split(
    train_features,
    train_label,
    test_size=VAL_SIZE,
    stratify=train_label,
    random_state=SEED)

# 加载dataset

train_ds = tf.data.Dataset.from_tensor_slices((train_features, train_label)) \
                            .batch(BATCH_SIZE) \
                            .prefetch(buffer_size = tf.data.experimental.AUTOTUNE)

valid_ds = tf.data.Dataset.from_tensor_slices((valid_features, valid_label)) \
                            .batch(BATCH_SIZE) \
                            .prefetch(buffer_size = tf.data.experimental.AUTOTUNE)

test_ds = tf.data.Dataset.from_tensor_slices((test_features, test_label)) \
                            .batch(BATCH_SIZE) \
                            .prefetch(buffer_size = tf.data.experimental.AUTOTUNE)


# 模型

inputs = layers.Input(shape=(LENGTH, 1), dtype='float32')
re_inputs = tf.reshape(inputs, [-1, WIDTH, HEIGHT, 1])
Conv_1 = layers.Conv2D(60, (2, 2), padding='same', activation='relu')(re_inputs)
pool_1 = layers.MaxPooling2D()(Conv_1)
Conv_2 = layers.Conv2D(200, (2, 2), padding='same', activation='relu')(pool_1)
pool_2 = layers.MaxPooling2D()(Conv_2)
Flat = layers.Flatten()(pool_2)
Dense_1 = layers.Dense(500, activation='relu')(Flat)
dropout = layers.Dropout(0.2)(Dense_1)
# Dense_2 = layers.Dense(50, activation='relu')(dropout)
outputs = layers.Dense(1, activation='sigmoid')(Dense_1)

model = models.Model(inputs=inputs, outputs=outputs)

model.compile(optimizer=tf.keras.optimizers.Nadam(LR),
                loss='binary_crossentropy',
                metrics=['accuracy'])

model.fit(train_ds,
        validation_data=valid_ds,
        # class_weight=class_weight_dict,
        epochs=EPOCH,
        workers=4,
        callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=6, min_delta=1e-4, mode='min'),
                  tf.keras.callbacks.ReduceLROnPlateau(monitor='val_loss', patience=4, factor=0.5, verbose=0)])

predict = model.evaluate(test_ds)
print(predict)

model.save('./models/histogram_{0:.2f}.h5'.format(predict[1]), save_format="tf")
