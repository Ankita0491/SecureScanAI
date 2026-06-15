from datasets import load_dataset
from sklearn.model_selection import train_test_split
import numpy as np

print("Loading SecVulEval...")

dataset = load_dataset(
    "arag0rn/SecVulEval",
    split="train"
)

df = dataset.to_pandas()

df = df[
    [
        "func_body",
        "is_vulnerable",
        "cwe_list",
        "hash"
    ]
]

df = df.dropna(
    subset=[
        "func_body",
        "cwe_list",
        "hash"
    ]
)

df = df[df["is_vulnerable"] == True]

df = df.drop_duplicates(
    subset=["hash"]
)


def extract_first_cwe(value):
    if isinstance(value, np.ndarray):
        if len(value) > 0:
            return str(value[0])
        return None

    if isinstance(value, list):
        if len(value) > 0:
            return str(value[0])
        return None

    if isinstance(value, str):
        return value

    return None


df["cwe"] = df["cwe_list"].apply(extract_first_cwe)

df = df.dropna(subset=["cwe"])

df = df.rename(
    columns={
        "func_body": "code"
    }
)

top_cwes = df["cwe"].value_counts().head(10).index

df = df[df["cwe"].isin(top_cwes)]

df = df[
    [
        "code",
        "cwe",
        "hash"
    ]
]

print("Rows:", len(df))
print("CWE distribution:")
print(df["cwe"].value_counts())

train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df["cwe"]
)

train_df.to_csv("cwe_train.csv", index=False)
test_df.to_csv("cwe_test.csv", index=False)

print("CWE dataset prepared.")
print("Saved cwe_train.csv")
print("Saved cwe_test.csv")