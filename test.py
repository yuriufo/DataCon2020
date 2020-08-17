import os
import time
import numpy as np
import pandas as pd
import pickle
from multiprocessing import Manager, Pool

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf

with open("/home/jovyan/models/hash_list.pkl", "rb") as f:
    hash_list = pickle.load(f)

# ---------------------直方图------------------------

start_time = time.time()

print("Histogram predict: {0:.2f}s".format(time.time()-start_time))

test_path = [os.path.join("/home/jovyan/histogram", sp) for sp in hash_list]

test_num = len(test_path)

raw_feature = np.empty((test_num, 512))

for i, fp in enumerate(test_path):
    with open(fp+'.txt', 'r') as f:
        feature = f.readlines()
    feature = [float(his.strip()) for his in feature]
    raw_feature[i] = feature

model = tf.keras.models.load_model('/home/jovyan/models/histogram_0.97.h5')

histogram_test = model.predict(raw_feature)

# ---------------------PE静态特征------------------------

print("PE raw predict: {0:.2f}s".format(time.time()-start_time))
start_time = time.time()
with open("/home/jovyan/models/raw_feature.pkl", "rb") as fp:
    pe_raw_models = pickle.load(fp)

with open("/home/jovyan/models/raw_feature_names.pkl", "rb") as fp:
    raw_feature_names = pickle.load(fp)

with open("/home/jovyan/models/rfc_pe_model.pkl", "rb") as f:
    rfc_pe_model = pickle.load(f)

with open("/home/jovyan/pe_raw/pe_raw_vectors.pkl", "rb") as f:
    pe_raw_vectors = pickle.load(f)

n_splits = 5
pe_raw_vectors = np.array(pe_raw_vectors, dtype=np.float32)

oof_test_skf = Manager().list([0] * n_splits) # np.empty((n_splits, test_num))
def pe_raw_predict(ind, model):
    oof_test_skf[ind] = model.predict(pe_raw_vectors)

stacking_test = []

for name in raw_feature_names:
    pool = Pool(5)
    for i, model in enumerate(pe_raw_models[name]):
        pool.apply_async(func=pe_raw_predict, args=(i, model))
    pool.close()
    pool.join()
    oof_test = np.array(list(oof_test_skf), dtype=np.float32).mean(axis=0)
    stacking_test.append(oof_test.reshape(-1, 1))

stacking_test = np.hstack(stacking_test)
raw_feature_test = rfc_pe_model.predict(stacking_test).reshape(-1, 1)

# ---------------------特征工程------------------------

print("Feature Engineering predict: {0:.2f}s".format(time.time()-start_time))
start_time = time.time()
with open("/home/jovyan/feature_engineering/feature_engineering_features.pkl", 'rb') as f:
    feature_engineering_features = pickle.load(f)

with open("/home/jovyan/models/keys.pkl", 'rb') as f:
    keys = pickle.load(f)

with open("/home/jovyan/models/lgb_models.pkl", "rb") as fp:
    lgb_models = pickle.load(fp)

train_df = pd.DataFrame(feature_engineering_features, columns=keys)

n_splits = 5

oof_test_skf = np.empty((n_splits, test_num))

for i, model in enumerate(lgb_models):
    oof_test_skf[i, :] = model.predict(train_df, num_iteration=model.best_iteration)

feature_engineerin_test = oof_test_skf.mean(axis=0).reshape(-1, 1)

# ---------------------融合------------------------

print("Final predict: {0:.2f}s".format(time.time()-start_time))
start_time = time.time()
with open("/home/jovyan/models/lr_rfc.pkl", "rb") as f:
    lr_rfc = pickle.load(f)

test = np.hstack([feature_engineerin_test, histogram_test , raw_feature_test])

labels_lr = lr_rfc[0].predict_proba(test)
labels_rfc = lr_rfc[1].predict_proba(test)

test_labels = []

for x, y in zip(labels_lr, labels_rfc):
    if x[1]*0.6+ y[1]*0.4  < 0.5:
        test_labels.append(0)
    else:
        test_labels.append(1)

print("Found {0} black samples. {1:.2f}s".format(sum(test_labels), time.time()-start_time))

result = []
for pt, label in zip(hash_list, test_labels):
    result.append("{0}, {1}\n".format(pt, label))
with open("/home/jovyan/malware_final.txt", 'w') as f:
    f.write(''.join(result).strip())
