from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import pandas as pd
import os
import pefile
import pickle
import csv
from scripts.preprocess import preprocess

views = Blueprint("views", __name__)

@views.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        uploaded_file = request.files["file"]
        if uploaded_file.filename != "":
            file_path = os.path.join("website/uploads", uploaded_file.filename)
            uploaded_file.save(file_path)

            pe = pefile.PE(file_path)

            model = pickle.load(open("models/xgb.pkl", "rb"))
            test_df = pd.DataFrame({"Name": [file_path]})
            result_df = preprocess(test_df)
            test = result_df.drop("Name", axis=1)
            result = model.predict(test)
            print(result)
            for i in range(len(result_df)):
                result_df.loc[i, "Label"] = "benign" if result[0] == 0 else "malware"

            return render_template("result.html", pe_info=result_df)

    return render_template("home.html")