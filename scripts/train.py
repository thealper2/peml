import pandas as pd
df = pd.read_csv("../datasets/file_pe.csv")
df.drop(["SuspiciousImportFunctions", "SuspiciousNameSection", "DirectoryEntryImportSize"], axis=1, inplace=True)

X = df.drop(["Name", "Malware"], axis=1)
y = df["Malware"]

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

from xgboost import XGBClassifier
model = XGBClassifier()
model.fit(X_train, y_train)

from sklearn.metrics import accuracy_score
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"[+] Model trained with {accuracy * 100: .2f}% accuracy")

import pickle
pickle.dump(model, open("../models/xgb.pkl", "wb"))
print("[+] Model saved as ../models/xgb.pkl")