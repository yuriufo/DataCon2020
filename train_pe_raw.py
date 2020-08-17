import os
import time
import copy
from tqdm import tqdm
import numpy as np
import pandas as pd
import pickle

import lief

from sklearn.model_selection import train_test_split
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import cross_validate
from sklearn.model_selection import GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn import svm
from sklearn import neighbors
from sklearn import naive_bayes
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.linear_model import LogisticRegressionCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.gaussian_process import GaussianProcessClassifier

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import BaggingClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import GradientBoostingClassifier

from sklearn import metrics
from sklearn.metrics import accuracy_score

from raw_features import PEFeatureExtractor

with open("/home/datacon/malware/XXX/black.txt", 'r') as f:
    black_list = f.read().strip().split()

with open("/home/datacon/malware/XXX/white.txt", 'r') as f:
    white_list = f.read().strip().split()

with open("models/hash_list.pkl", 'rb') as f:
    hash_list = pickle.load(f)

train_features = []
for ha in hash_list:
    if ha in black_list:
        train_features.append(1)
    else:
        train_features.append(0)

train_features = np.array(train_features, dtype=np.int32)

pe = PEFeatureExtractor()

with open("/home/jovyan/pe_raw/pe_raw_vectors.pkl", "rb") as f:
    pe_raw_vectors = pickle.load(f)

# pe_raw_vectors = np.array(pe_raw_vectors, dtype=np.float32)

pe_raw_feature_train = np.array(pe_raw_vectors, dtype=np.float32)
pe_raw_feature_test = np.empty((10, 967), dtype=np.float32)
pe_raw_feature_label = train_features


# 所用模型
bc_model = BaggingClassifier(n_estimators=100)
gbc_model = GradientBoostingClassifier()
lr_model = LogisticRegression(max_iter=5000)
svm_model = svm.LinearSVC(max_iter=10000)
dt_model = DecisionTreeClassifier()
xgb_model = XGBClassifier(max_depth=7, learning_rate=0.05, n_estimators=500)

rfc_model = RandomForestClassifier(200)
etc_model = ExtraTreesClassifier()
mnb_model = naive_bayes.MultinomialNB(alpha=0.01)
ada_model = AdaBoostClassifier()

pe_raw_models = {}

def get_oof(model, x_train, y_train, x_test, n_splits):
    score = []
    n_train, n_test = x_train.shape[0], x_test.shape[0]
    kf = StratifiedKFold(n_splits=n_splits, random_state=0, shuffle=True)
    oof_train = np.empty((n_train, ))
    oof_test = np.empty((n_test, ))
    oof_test_skf = np.empty((n_splits, n_test))
    models = []
    with tqdm(total=n_splits, ncols=80) as pbar:
        for i, (train_index, test_index) in enumerate(kf.split(x_train, y_train)):
            kf_x_train = x_train[train_index]
            kf_y_train = y_train[train_index]
            kf_x_test = x_train[test_index]
            model.fit(kf_x_train, kf_y_train)
            oof_train[test_index] = model.predict(kf_x_test)
            oof_test_skf[i, :] = model.predict(x_test)
            score.append(model.score(kf_x_train, kf_y_train))
            models.append(copy.deepcopy(model))
            pbar.update(1)
        oof_test[:] = oof_test_skf.mean(axis=0)
    return oof_train.reshape(-1, 1), oof_test.reshape(-1, 1), models, np.mean(score)


try:
    svm_model_oof_train, svm_model_oof_test, models, score = get_oof(svm_model, 
                                                                                  pe_raw_feature_train, 
                                                                                  pe_raw_feature_label,
                                                                                  pe_raw_feature_test,
                                                                                  5)
    pe_raw_models['svm'] = models
    print("svm success! {}".format(score))
except Exception as e:
    print("svm error! {}".format(e))

try:
    dt_model_oof_train, dt_model_oof_test, models, score = get_oof(dt_model, 
                                                                            pe_raw_feature_train, 
                                                                            pe_raw_feature_label,
                                                                            pe_raw_feature_test,
                                                                            5)
    pe_raw_models['dt'] = models
    print("dt success! {}".format(score))
except Exception as e:
    print("dt error! {}".format(e))

try:
    rfc_model_oof_train, rfc_model_oof_test, models, score = get_oof(rfc_model, 
                                                                                  pe_raw_feature_train, 
                                                                                  pe_raw_feature_label,
                                                                                  pe_raw_feature_test,
                                                                                  5)
    pe_raw_models['rfc'] = models
    print("rfc success! {}".format(score))
except Exception as e:
    print("rfc error! {}".format(e))

try:
    etc_model_oof_train, etc_model_oof_test, models, score = get_oof(etc_model, 
                                                                                  pe_raw_feature_train, 
                                                                                  pe_raw_feature_label,
                                                                                  pe_raw_feature_test,
                                                                                  5)
    pe_raw_models['etc'] = models
    print("etc success! {}".format(score))
except Exception as e:
    print("etc error! {}".format(e))

# try:
#     mnb_model_oof_train, mnb_model_oof_test, models, score = get_oof(mnb_model, 
#                                                                                   pe_raw_feature_train, 
#                                                                                   pe_raw_feature_label,
#                                                                                   pe_raw_feature_test,
#                                                                                   5)
#     # pe_raw_models['mnb'] = models
#     print("mnb success! {}".format(score))
# except Exception as e:
#     print("mnb error! {}".format(e))

try:
    ada_model_oof_train, ada_model_oof_test, models, score = get_oof(ada_model, 
                                                                                  pe_raw_feature_train, 
                                                                                  pe_raw_feature_label,
                                                                                  pe_raw_feature_test,
                                                                                  5)
    pe_raw_models['ada'] = models
    print("ada success! {}".format(score))
except Exception as e:
    print("ada error! {}".format(e))

try:
    xgb_model_oof_train, xgb_model_oof_test, models, score = get_oof(xgb_model, 
                                                                                  pe_raw_feature_train, 
                                                                                  pe_raw_feature_label,
                                                                                  pe_raw_feature_test,
                                                                                  5)
    pe_raw_models['xgb'] = models
    print("xgb success! {}".format(score))
except Exception as e:
    print("xgb error! {}".format(e))

try:
    lr_model_oof_train, lr_model_oof_test, models, score = get_oof(lr_model, 
                                                                        pe_raw_feature_train, 
                                                                        pe_raw_feature_label,
                                                                        pe_raw_feature_test,
                                                                        5)
    pe_raw_models['lr'] = models
    print("lr success! {}".format(score))
except Exception as e:
    print("lr error! {}".format(e))

try:
    gbc_model_oof_train, gbc_model_oof_test, models, score = get_oof(gbc_model, 
                                                                      pe_raw_feature_train, 
                                                                      pe_raw_feature_label,
                                                                      pe_raw_feature_test,
                                                                      5)
    pe_raw_models['gbc'] = models
    print("gbc success! {}".format(score))
except Exception as e:
    print("gbc error! {}".format(e))
    
try:
    bc_model_oof_train, bc_model_oof_test, models, score = get_oof(bc_model, 
                                                                            pe_raw_feature_train, 
                                                                            pe_raw_feature_label,
                                                                            pe_raw_feature_test,
                                                                            5)
    pe_raw_models['bc'] = models
    print("bc success! {}".format(score))
except Exception as e:
    print("bc error! {}".format(e))
    
with open("models/raw_feature.pkl", "wb") as fp:
    pickle.dump(pe_raw_models, fp)

# with open("models/raw_feature_names.pkl", "wb") as fp:
#     pickle.dump(['lr', 'gbc', 'bc', 'xgb', 'dt', 'svm', 'rfc', 'etc', 'ada'], fp)

raw_feature_stacking_train_5 = np.hstack([lr_model_oof_train, gbc_model_oof_train, bc_model_oof_train,
                                            xgb_model_oof_train, dt_model_oof_train, svm_model_oof_train,
                                            rfc_model_oof_train, etc_model_oof_train, # mnb_model_oof_train,
                                            ada_model_oof_train])

with open("oof/raw_feature_stacking_train_5.pkl", "wb") as fp:
    pickle.dump(raw_feature_stacking_train_5, fp)

