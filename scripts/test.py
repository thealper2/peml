import numpy as np
import pandas as pd
import pefile
import pickle
import sys
from preprocess import preprocess

def test(file_path):
    test_df = pd.DataFrame({"Name": [file_path]})
    result_df = preprocess(test_df)
    model = pickle.load(open("../models/xgb.pkl", "rb"))
    test = result_df.drop("Name", axis=1)
    result = model.predict(test)
    if result[0] == 0:
        print(f"[+] File: {file_path} is benign.")
    else:
        print(f"[-] File: {file_path} is malware.")
        
    for i in range(len(result_df)):
        result_df.loc[i, "Label"] = "benign" if result[0] == 0 else "malware"
    result_df.to_csv("../reports/report.csv")
    print("[+] Report saved as: ../reports/report.csv")

if __name__ == "__main__":
    file_path = sys.argv[1]
    test(file_path)
