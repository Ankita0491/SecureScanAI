import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score

print("Loading CWE dataset...")

train_df = pd.read_csv("cwe_train.csv")
test_df = pd.read_csv("cwe_test.csv")

X_train = train_df["code"].astype(str)
X_test = test_df["code"].astype(str)

label_encoder = LabelEncoder()

y_train = label_encoder.fit_transform(train_df["cwe"])
y_test = label_encoder.transform(test_df["cwe"])

print("Classes:")
print(label_encoder.classes_)

vectorizer = TfidfVectorizer(
    max_features=50000,
    ngram_range=(1, 2)
)

print("Vectorizing...")

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print("Training model...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train_vec, y_train)

predictions = model.predict(X_test_vec)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nAccuracy:", accuracy)

print(
    classification_report(
        y_test,
        predictions,
        target_names=label_encoder.classes_
    )
)

joblib.dump(
    model,
    "cwe_model.pkl"
)

joblib.dump(
    vectorizer,
    "cwe_vectorizer.pkl"
)

joblib.dump(
    label_encoder,
    "cwe_label_encoder.pkl"
)

print("\nSaved:")
print("cwe_model.pkl")
print("cwe_vectorizer.pkl")
print("cwe_label_encoder.pkl")