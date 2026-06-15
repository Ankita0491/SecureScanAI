import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix


print("Loading train.csv and test.csv...")

train_df = pd.read_csv("train.csv")
test_df = pd.read_csv("test.csv")

print("Train rows:", len(train_df))
print("Test rows:", len(test_df))

X_train = train_df["code"].astype(str)
y_train = train_df["label"]

X_test = test_df["code"].astype(str)
y_test = test_df["label"]


print("Creating TF-IDF features...")

vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(3, 6),
    max_features=100000,
    lowercase=False
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)


print("Training Logistic Regression model...")

model = LogisticRegression(
    max_iter=3000,
    class_weight="balanced",
    solver="saga"
)

model.fit(X_train_vec, y_train)


print("Evaluating model...")

predictions = model.predict(X_test_vec)

accuracy = accuracy_score(y_test, predictions)

print("Accuracy:", accuracy)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Safe",
            "Vulnerable"
        ]
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))


print("Saving model and vectorizer...")

joblib.dump(model, "baseline_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("Training completed.")
print("Saved: baseline_model.pkl")
print("Saved: tfidf_vectorizer.pkl")