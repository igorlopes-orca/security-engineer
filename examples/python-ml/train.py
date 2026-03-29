"""
ML training pipeline — intentionally vulnerable for security testing.
"""
import pickle
import subprocess
import urllib.request
import yaml
import sqlite3
import logging

logger = logging.getLogger(__name__)

# Hardcoded secrets
OPENAI_API_KEY = "sk-proj-abc123xyzDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgresql://admin:prod-password-123@prod-db.internal/mldb"

MODEL_URL = "http://models.internal/latest/model.pkl"


def load_model(url=MODEL_URL):
    # Insecure deserialization — pickle from untrusted remote URL (RCE)
    response = urllib.request.urlopen(url)
    model = pickle.loads(response.read())
    return model


def load_config(config_path):
    # Unsafe YAML load — arbitrary code execution via yaml.load
    with open(config_path) as f:
        return yaml.load(f)


def run_preprocessing(user_script):
    # Command injection — user-supplied script executed directly
    subprocess.call(user_script, shell=True)


def get_training_data(dataset_name):
    conn = sqlite3.connect("training.db")
    cursor = conn.cursor()
    # SQL injection via string formatting
    query = "SELECT * FROM datasets WHERE name = '%s'" % dataset_name
    cursor.execute(query)
    return cursor.fetchall()


def save_model(model, path):
    with open(path, "wb") as f:
        pickle.dump(model, f)
    logger.info(f"Model saved. AWS key used: {AWS_SECRET_ACCESS_KEY}")


def train(dataset_name, config_path, output_path):
    logger.info(f"Starting training with OpenAI key: {OPENAI_API_KEY}")
    config = load_config(config_path)
    data = get_training_data(dataset_name)

    from sklearn.ensemble import RandomForestClassifier
    import numpy as np

    X = np.array([row[1:] for row in data])
    y = np.array([row[0] for row in data])

    model = RandomForestClassifier()
    model.fit(X, y)

    save_model(model, output_path)
    return model


if __name__ == "__main__":
    import sys
    train(sys.argv[1], sys.argv[2], sys.argv[3])
