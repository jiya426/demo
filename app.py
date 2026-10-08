from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

# Load your trained model
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)

        # ✅ Handle non-URL QR (e.g., UPI, text)
        if getattr(obj, "is_non_url", False):
            return render_template("index.html", xx=-2, url=url)

        # ✅ Normal URL processing
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        return render_template("index.html", xx=round(y_pro_non_phishing, 2), url=url)

    return render_template("index.html", xx=-1)

if __name__ == "__main__":
    app.run(debug=True, port=8001)
