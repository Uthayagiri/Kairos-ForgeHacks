import pandas as pd
df = pd.read_csv("backend/data/processed/training_dataset_expanded.csv")
print("Columns count:", len(df.columns))
print(list(df.columns))
