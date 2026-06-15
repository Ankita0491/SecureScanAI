from datasets import load_dataset
from sklearn.model_selection import train_test_split

print("Downloading SecVulEval dataset...")

dataset = load_dataset(
    "arag0rn/SecVulEval",
    split="train"
)

print("Converting dataset...")
df = dataset.to_pandas()

print("Original rows:", len(df))

required_columns = [
    "func_body",
    "is_vulnerable",
    "hash"
]

df = df[required_columns]

df = df.dropna(
    subset=[
        "func_body",
        "is_vulnerable",
        "hash"
    ]
)

df = df.drop_duplicates(
    subset=["hash"]
)

df["label"] = df["is_vulnerable"].astype(int)

df = df.rename(
    columns={
        "func_body": "code"
    }
)

df = df[
    [
        "code",
        "label",
        "hash"
    ]
]

print("Rows after cleaning:", len(df))
print("Class count:")
print(df["label"].value_counts())

train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

train_df.to_csv(
    "train.csv",
    index=False
)

test_df.to_csv(
    "test.csv",
    index=False
)

print("Dataset preparation completed.")
print("train.csv rows:", len(train_df))
print("test.csv rows:", len(test_df))