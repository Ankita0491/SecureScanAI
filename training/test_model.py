import joblib

print("Loading saved model...")

model = joblib.load("baseline_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")


def predict_code(code):
    code_vector = vectorizer.transform([code])

    prediction = model.predict(code_vector)[0]
    probability = model.predict_proba(code_vector)[0]

    confidence = max(probability) * 100

    if prediction == 1:
        status = "Vulnerable"
    else:
        status = "Safe"

    return status, confidence


vulnerable_code = """
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    gets(buffer);
    strcpy(buffer, "very long unsafe input");
    return 0;
}
"""

safe_code = """
#include <stdio.h>

int main() {
    printf("Hello World");
    return 0;
}
"""


print("\nTesting vulnerable code:")
status, confidence = predict_code(vulnerable_code)
print("Status:", status)
print("Confidence:", round(confidence, 2), "%")


print("\nTesting safe code:")
status, confidence = predict_code(safe_code)
print("Status:", status)
print("Confidence:", round(confidence, 2), "%")