import shap
import matplotlib.pyplot as plt
from ripser import ripser
from persim import plot_diagrams

import numpy as np


def compute_shap_values(model, X_test, class_index=1):
    """
    Computes SHAP values for the given model using TreeExplainer.
    
    Parameters:
        model: Trained tree-based model.
        X_test: Test dataset.
        class_index (int): For classification tasks, index of the target class's SHAP values.
        
    Returns:
        Array of SHAP values corresponding to the specified class.
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test)
    return shap_values[:, :, class_index]


def plot_shap_summary(shap_values, X_test, title, feature_names, filename):
    """
    Generates a SHAP summary plot and saves it as an image.
    
    Parameters:
        shap_values: Array of SHAP values.
        X_test: Test dataset.
        title (str): Title for the plot.
        feature_names (list): List of feature names.
        filename (str): The filename to save the image (e.g., 'shap_summary.png').
    """
    # Create a SHAP Explanation object
    explanation = shap.Explanation(values=shap_values,
                                data=X_test,
                                feature_names=feature_names)
    # Generate summary plot without showing it
    # Using the new beeswarm plot directly:
    shap.plots.beeswarm(explanation, show=False)
    plt.title(title)
    # Save the figure to a file instead of displaying it
    plt.savefig(filename, bbox_inches="tight")
    plt.close()
    print(f"Saved SHAP summary plot to {filename}")


def compute_persistent_diagrams(shap_values):
    """
    Computes the persistent homology diagrams using ripser on the SHAP values.
    
    Parameters:
        shap_values: Array of SHAP values.
        
    Returns:
        A dictionary containing persistence diagrams.
    """
    results = ripser(shap_values)
    return results['dgms']


def plot_persistence_diagrams(diagrams_clean, diagrams_poisoned, filename):
    """
    Plots persistence diagrams for both clean and poisoned models side by side and saves the image.
    
    Parameters:
        diagrams_clean: Persistence diagrams for the clean model.
        diagrams_poisoned: Persistence diagrams for the poisoned model.
        filename (str): The filename to save the image (e.g., 'persistence_diagrams.png').
    """
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    plot_diagrams(diagrams_clean, show=False)
    plt.title("Persistence Diagram: Clean Model SHAP Values")
    
    plt.subplot(1, 2, 2)
    plot_diagrams(diagrams_poisoned, show=False)
    plt.title("Persistence Diagram: Poisoned Model SHAP Values")
    
    plt.savefig(filename, bbox_inches='tight')
    plt.close()
    print(f"Saved persistence diagrams plot to {filename}")

def plot_combined_shap_summary(shap_values_clean, shap_values_poisoned, X_test, feature_names, filename):
    """
    Generates a combined SHAP summary plot for both clean and poisoned models 
    side by side and saves it as an image.
    
    This function uses shap.plots.beeswarm (the newer SHAP plotting API) which 
    accepts an axis parameter.
    
    Parameters:
        shap_values_clean (ndarray): SHAP values from the clean model.
        shap_values_poisoned (ndarray): SHAP values from the poisoned model.
        X_test (DataFrame): Test dataset (used for feature names).
        feature_names (list): List of feature names.
        filename (str): The filename to save the image.
    """
    # Create Explanation objects from the raw SHAP values.
    # This requires X_test to be a DataFrame with column names.
    explanation_clean = shap.Explanation(values=shap_values_clean, 
                                          data=X_test, 
                                          feature_names=feature_names)
    explanation_poisoned = shap.Explanation(values=shap_values_poisoned, 
                                             data=X_test, 
                                             feature_names=feature_names)
    
    # Create a figure with two subplots side by side.
    plt.figure(figsize=(16, 8))
    
    # Left subplot for the clean model.
    plt.subplot(1, 2, 1)
    # Call beeswarm without an axis parameter and set plot_size to None.
    shap.plots.beeswarm(explanation_clean, show=False, plot_size=None)
    plt.title("Clean Model SHAP Summary")
    
    # Right subplot for the poisoned model.
    plt.subplot(1, 2, 2)
    shap.plots.beeswarm(explanation_poisoned, show=False, plot_size=None)
    plt.title("Poisoned Model SHAP Summary")
    
    plt.tight_layout()
    plt.savefig(filename, bbox_inches="tight")
    plt.close()
    print(f"Saved combined SHAP summaries plot to {filename}")


def run_analysis(clean_model, poisoned_model, X_test, feature_columns):
    """
    Runs the complete analysis:
      - Computes and plots SHAP summary plots for both models.
      - Computes and plots persistence diagrams using TDA on the SHAP value space.
    
    Parameters:
        clean_model: The trained clean model.
        poisoned_model: The trained poisoned model.
        X_test: Test dataset.
        feature_columns: List of feature names.
    """
    # Compute SHAP values for each model
    shap_values_clean = compute_shap_values(clean_model, X_test, class_index=1)
    shap_values_poisoned = compute_shap_values(poisoned_model, X_test, class_index=1)

    # Ensure shap consistency.
    print("shap_values Clean shape:", np.array(shap_values_clean).shape)
    print("shap_values Poisoned shape:", np.array(shap_values_poisoned).shape)
    print("X_test shape:", X_test.shape)
    
    # Save SHAP summary plots
    print("Saving SHAP Summary Plots...")
    plot_shap_summary(shap_values_clean, X_test, "SHAP Summary for Clean Model", feature_columns, "shap_summary_clean.png")
    plot_shap_summary(shap_values_poisoned, X_test, "SHAP Summary for Poisoned Model", feature_columns, "shap_summary_poisoned.png")
    
    # Generate and save a combined SHAP summary plot (side by side)
    print("Saving combined SHAP Summary Plot...")
    plot_combined_shap_summary(shap_values_clean, shap_values_poisoned, X_test, feature_columns, "combined_shap_summary.png")
    
    # Compute persistent diagrams using ripser
    print("Computing Persistent Diagrams...")
    diagrams_clean = compute_persistent_diagrams(shap_values_clean)
    diagrams_poisoned = compute_persistent_diagrams(shap_values_poisoned)
    
    # Save persistence diagrams side by side
    print("Saving Persistence Diagrams...")
    plot_persistence_diagrams(diagrams_clean, diagrams_poisoned, "persistence_diagrams.png")


# Example usage:
# clean_model = load_model('path_to_clean_model.joblib')
# poisoned_model = load_model('path_to_poisoned_model.joblib')
# X_test = ...  # Your test dataset
# run_analysis(clean_model, poisoned_model, X_test)
