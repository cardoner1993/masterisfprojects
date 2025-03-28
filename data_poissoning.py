import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix, RocCurveDisplay
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
import joblib


def load_and_preprocess_data(csv_path):
    """
    Loads the dataset from a CSV file, removes non-numeric columns, handles missing values,
    and returns feature and label arrays.

    Parameters:
        csv_path (str): Path to the dataset CSV file.

    Returns:
        X (DataFrame): Features.
        y (Series): Labels.
    """
    data = pd.read_csv(csv_path)
    data = data.dropna()
    y = data['Malware']
    X = data.drop(columns=['Malware'])

    # Drop non-numeric columns
    non_numeric = X.select_dtypes(include=['object']).columns
    if len(non_numeric) > 0:
        print(f"Removing non-numeric columns: {list(non_numeric)}")
        X = X.drop(columns=non_numeric)

    return X, y


def split_and_scale_data(X, y):
    """
    Splits the data into training and testing sets and applies standard scaling.

    Parameters:
        X (DataFrame): Features.
        y (Series): Labels.

    Returns:
        X_train_scaled, X_test_scaled, y_train, y_test
    """
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled, y_train, y_test


def train_model(X_train, y_train):
    """
    Trains a Random Forest model.

    Parameters:
        X_train (ndarray): Training features.
        y_train (Series): Training labels.

    Returns:
        RandomForestClassifier: Trained model.
    """
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model


def evaluate_model(model, X_test, y_test, title="Model"):
    """
    Evaluates the model and prints accuracy, AUC, classification report, and confusion matrix.

    Parameters:
        model (RandomForestClassifier): Trained model.
        X_test (ndarray): Testing features.
        y_test (Series): Testing labels.
        title (str): Title for the output display.
    """
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    print(f"\n{title} Results:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("AUC:", roc_auc_score(y_test, y_prob))
    print("Classification Report:\n", classification_report(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='OrRd', xticklabels=['Benign', 'Malware'], yticklabels=['Benign', 'Malware'])
    plt.title(f"{title} Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()


def poison_data(X_train, y_train, poison_fraction=0.2):
    """
    Simulates a data poisoning attack by flipping a fraction of malicious labels to benign.

    Parameters:
        X_train (ndarray): Training features.
        y_train (Series): Training labels.
        poison_fraction (float): Fraction of malicious samples to poison.

    Returns:
        X_train_poisoned, y_train_poisoned
    """
    X_train_poisoned = X_train.copy()
    y_train_poisoned = y_train.copy()
    malicious_indices = np.where(y_train_poisoned == 1)[0]
    num_poison = int(poison_fraction * len(malicious_indices))
    np.random.seed(42)
    poison_indices = np.random.choice(malicious_indices, num_poison, replace=False)
    y_train_poisoned.iloc[poison_indices] = 0
    print(f"Poisoned {num_poison} malicious samples.")
    return X_train_poisoned, y_train_poisoned


def save_model(model, filename):
    """
    Saves the trained model to disk.

    Parameters:
        model (RandomForestClassifier): Trained model.
        filename (str): Path to save the model file.
    """
    joblib.dump(model, filename)


def plot_label_distribution(y_clean, y_poisoned):
    """
    Compares the label distribution before and after poisoning.
    """
    plt.figure(figsize=(8, 4))
    plt.hist([y_clean, y_poisoned], bins=[-0.5, 0.5, 1.5], label=["Clean", "Poisoned"], rwidth=0.4)
    plt.xticks([0, 1], ['Benign', 'Malware'])
    plt.title("Label Distribution Before vs After Poisoning")
    plt.ylabel("Sample Count")
    plt.legend()
    plt.grid(True)
    plt.show()


def plot_roc_curves(model_clean, model_poisoned, X_test, y_test):
    """
    Plots ROC curves for both clean and poisoned models.
    """
    RocCurveDisplay.from_estimator(model_clean, X_test, y_test, name="Clean Model")
    RocCurveDisplay.from_estimator(model_poisoned, X_test, y_test, name="Poisoned Model")
    plt.title("ROC Curve Comparison")
    plt.grid(True)
    plt.show()


def compare_confusion_matrices(y_true, y_pred_clean, y_pred_poisoned):
    """
    Plots side-by-side confusion matrices for clean vs poisoned models.
    """
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    sns.heatmap(confusion_matrix(y_true, y_pred_clean), annot=True, fmt='d', ax=axes[0], cmap='Blues', xticklabels=['Benign', 'Malware'], yticklabels=['Benign', 'Malware'])
    axes[0].set_title("Clean Model")
    axes[0].set_xlabel("Predicted")
    axes[0].set_ylabel("Actual")

    sns.heatmap(confusion_matrix(y_true, y_pred_poisoned), annot=True, fmt='d', ax=axes[1], cmap='OrRd', xticklabels=['Benign', 'Malware'], yticklabels=['Benign', 'Malware'])
    axes[1].set_title("Poisoned Model")
    axes[1].set_xlabel("Predicted")
    axes[1].set_ylabel("Actual")
    plt.tight_layout()
    plt.show()


def plot_pca(X, y, title="PCA of Dataset"):
    """
    Plots a 2D PCA projection of the dataset.
    """
    pca = PCA(n_components=2)
    X_reduced = pca.fit_transform(X)
    plt.figure(figsize=(8, 6))
    scatter = plt.scatter(X_reduced[:, 0], X_reduced[:, 1], c=y, cmap='coolwarm', alpha=0.6)
    plt.legend(*scatter.legend_elements(), title="Class")
    plt.title(title)
    plt.xlabel("PCA 1")
    plt.ylabel("PCA 2")
    plt.grid(True)
    plt.show()


# Example usage:
if __name__ == "__main__":
    X, y = load_and_preprocess_data("dataset_malwares.csv")
    X_train, X_test, y_train, y_test = split_and_scale_data(X, y)

    # Train clean model
    clean_model = train_model(X_train, y_train)
    evaluate_model(clean_model, X_test, y_test, title="Clean Model")
    save_model(clean_model, "clean_model.pkl")

    # Poisoned training data and model
    X_poisoned, y_poisoned = poison_data(X_train, y_train)
    poisoned_model = train_model(X_poisoned, y_poisoned)
    evaluate_model(poisoned_model, X_test, y_test, title="Poisoned Model")
    save_model(poisoned_model, "poisoned_model.pkl")

    # Visualization
    plot_label_distribution(y_train, y_poisoned)
    y_pred_clean = clean_model.predict(X_test)
    y_pred_poisoned = poisoned_model.predict(X_test)
    compare_confusion_matrices(y_test, y_pred_clean, y_pred_poisoned)