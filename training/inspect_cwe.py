from datasets import load_dataset

dataset = load_dataset(
    "arag0rn/SecVulEval",
    split="train"
)

df = dataset.to_pandas()

print("Columns:")
print(df.columns)

print("\nTotal rows:", len(df))

print("\nis_vulnerable counts:")
print(df["is_vulnerable"].value_counts(dropna=False))

print("\nFirst 20 cwe_list values:")
print(df["cwe_list"].head(20).to_list())

print("\nCWE type:")
print(type(df["cwe_list"].iloc[0]))

print("\nNon-null cwe count:")
print(df["cwe_list"].notna().sum())