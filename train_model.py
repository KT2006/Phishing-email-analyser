# Step 1: Import libraries
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, precision_recall_curve
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
import joblib
import re
import os
import glob
from urllib.parse import urlparse
import tldextract
from collections import Counter

def load_and_combine_datasets():
    """Load and combine existing and new datasets"""
    datasets = []
    
    # Load existing dataset
    if os.path.exists('emails.csv'):
        main_data = pd.read_csv('emails.csv')
        datasets.append(main_data)
        print(f"Loaded existing dataset with {len(main_data)} samples")
    
    # Load spam dataset
    if os.path.exists('spam-emails.csv'):
        try:
            spam_data = pd.read_csv('spam-emails.csv')
            # Ensure the data has the required columns
            required_cols = ['sender', 'subject', 'body', 'label']
            if all(col in spam_data.columns for col in required_cols):
                datasets.append(spam_data)
                print(f"Loaded spam dataset with {len(spam_data)} samples")
            else:
                print("Warning: spam-emails.csv missing required columns")
        except Exception as e:
            print(f"Error loading spam-emails.csv: {e}")
    
    # Load Enron dataset
    if os.path.exists('enron-emails.csv'):
        enron_data = pd.read_csv('enron-emails.csv')
        datasets.append(enron_data)
        print(f"Loaded enron-emails.csv with {len(enron_data)} samples")
    
    if not datasets:
        raise ValueError("No datasets found!")
    
    # Combine all datasets
    combined_data = pd.concat(datasets, ignore_index=True)
    print(f"\nTotal samples after combining: {len(combined_data)}")
    
    # Print class distribution
    print("\nClass distribution in combined dataset:")
    print(combined_data['label'].value_counts())
    
    return combined_data

def extract_advanced_features(row):
    """Extract advanced features from email data"""
    sender = str(row['sender']) if pd.notna(row['sender']) else ''
    body = str(row['body']) if pd.notna(row['body']) else ''
    subject = str(row['subject']) if pd.notna(row['subject']) else ''
    
    features = {}
    
    # Basic sender features
    features['sender_length'] = len(sender)
    features['sender_has_numbers'] = 1 if re.search(r'\d', sender) else 0
    
    # Enhanced TLD analysis
    if '@' in sender:
        domain = sender.split('@')[-1].split('>')[0].strip()
        tld_info = tldextract.extract(domain)
        features['sender_domain_length'] = len(domain)
        features['sender_tld_length'] = len(tld_info.suffix)
        features['sender_suspicious_tld'] = 1 if any(tld in tld_info.suffix.lower() for tld in ['.tk', '.ml', '.cf', '.ga', '.pw', '.xyz', '.top', '.work', '.click', '.info', '.biz', '.online', '.site', '.website']) else 0
        features['sender_common_domain'] = 1 if any(common in tld_info.domain.lower() for common in ['gmail', 'yahoo', 'hotmail', 'outlook', 'protonmail', 'icloud']) else 0
    else:
        features['sender_domain_length'] = 0
        features['sender_tld_length'] = 0
        features['sender_suspicious_tld'] = 0
        features['sender_common_domain'] = 0
    
    # URL analysis
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls_found = re.findall(url_pattern, body + ' ' + subject)
    
    features['has_urls'] = 1 if urls_found else 0
    features['num_urls'] = len(urls_found)
    
    # Enhanced URL analysis
    if urls_found:
        url_domains = []
        for url in urls_found:
            try:
                netloc = urlparse(url).netloc
                url_domains.append(netloc)
            except ValueError:
                # Skip invalid URLs that cause urlparse to fail
                continue
        features['url_domain_count'] = len(set(url_domains))
        features['suspicious_url_domains'] = sum(1 for domain in url_domains if any(tld in domain.lower() for tld in ['.tk', '.ml', '.cf', '.ga', '.pw', '.xyz', '.top', '.work', '.click']))
    else:
        features['url_domain_count'] = 0
        features['suspicious_url_domains'] = 0
    
    # Enhanced suspicious URL patterns
    suspicious_url_patterns = [
        r'verify', r'login', r'secure', r'account', r'confirm', r'update',
        r'password', r'security', r'validate', r'check', r'verify-account',
        r'urgent', r'action-required', r'secure-login', r'payment', r'bank',
        r'credit', r'card', r'password', r'reset', r'change', r'update',
        r'verify-email', r'confirm-email', r'account-verification',
        r'security-check', r'fraud', r'suspicious', r'alert'
    ]
    features['suspicious_url_patterns'] = sum(1 for url in urls_found if any(pattern in url.lower() for pattern in suspicious_url_patterns))
    
    # Content analysis
    full_text = body + ' ' + subject
    
    # Enhanced urgency words
    urgency_words = [
        'urgent', 'immediate', 'asap', 'important', 'action required',
        'verify now', 'suspended', 'blocked', 'expire', 'limited time',
        'last chance', 'final notice', 'immediately', 'right now',
        'today only', 'expiring soon', 'act now', 'don\'t delay',
        'time sensitive', 'critical', 'emergency'
    ]
    features['urgency_words'] = sum(1 for word in urgency_words if word in full_text.lower())
    
    # Enhanced threat words
    threat_words = [
        'suspended', 'blocked', 'closed', 'terminated', 'expire',
        'lose', 'permanent', 'immediately', 'verify', 'confirm',
        'unauthorized', 'fraud', 'suspicious', 'compromise',
        'breach', 'hack', 'stolen', 'locked', 'restricted',
        'violation', 'penalty', 'fine', 'legal action'
    ]
    features['threat_words'] = sum(1 for word in threat_words if word in full_text.lower())
    
    # Enhanced grammar and formatting checks
    grammar_patterns = [
        r'\b(?:you\s+must|click\s+here|verify\s+now|account\s+suspended)\b',
        r'\b(?:dear\s+customer|dear\s+user|dear\s+sir/madam)\b',
        r'\b(?:kindly\s+verify|please\s+confirm|urgently\s+required)\b',
        r'\b(?:your\s+account|your\s+password|your\s+security)\b',
        r'\b(?:click\s+below|click\s+link|click\s+button)\b'
    ]
    features['has_grammar_errors'] = 1 if any(re.search(pattern, full_text.lower()) for pattern in grammar_patterns) else 0
    
    # Enhanced brand analysis
    brand_names = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
        'bank', 'chase', 'wellsfargo', 'citi', 'ebay', 'linkedin',
        'facebook', 'twitter', 'instagram', 'whatsapp', 'telegram',
        'dropbox', 'spotify', 'uber', 'lyft', 'airbnb'
    ]
    features['brand_mentions'] = sum(1 for brand in brand_names if brand in full_text.lower())
    
    # Enhanced domain mismatch check
    if features['brand_mentions'] > 0:
        brand_domains = {
            'paypal': ['paypal.com', 'paypal.co.uk', 'paypal.me'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca'],
            'apple': ['apple.com', 'icloud.com', 'appleid.apple.com'],
            'microsoft': ['microsoft.com', 'outlook.com', 'office.com'],
            'google': ['google.com', 'gmail.com', 'accounts.google.com'],
            'netflix': ['netflix.com', 'netflix.net'],
            'chase': ['chase.com', 'chaseonline.com'],
            'wellsfargo': ['wellsfargo.com', 'wellsfargoadvisors.com'],
            'citi': ['citi.com', 'citibank.com'],
            'ebay': ['ebay.com', 'ebay.co.uk'],
            'linkedin': ['linkedin.com', 'linkedinmail.com']
        }
        features['domain_mismatch'] = 1 if any(
            brand in full_text.lower() and not any(domain in sender.lower() for domain in domains)
            for brand, domains in brand_domains.items()
        ) else 0
    else:
        features['domain_mismatch'] = 0
    
    # New features
    # Email formatting analysis
    features['suspicious_formatting'] = 1 if (
        re.search(r'[A-Z]{3,}', subject) or  # ALL CAPS in subject
        re.search(r'[!]{2,}', subject) or    # Multiple exclamation marks
        re.search(r'[?]{2,}', subject) or    # Multiple question marks
        len(subject.split()) > 15            # Very long subject
    ) else 0
    
    # Suspicious patterns
    features['suspicious_patterns'] = 1 if (
        re.search(r'\b(?:click|verify|confirm|update|login|password)\b.*\b(?:now|immediately|urgently|asap)\b', full_text.lower()) or
        re.search(r'\b(?:account|security|verification)\b.*\b(?:required|needed|mandatory)\b', full_text.lower()) or
        re.search(r'\b(?:suspended|blocked|locked|terminated)\b.*\b(?:account|access|service)\b', full_text.lower())
    ) else 0
    
    # Text statistics
    features['text_length'] = len(full_text)
    features['word_count'] = len(full_text.split())
    features['avg_word_length'] = np.mean([len(word) for word in full_text.split()]) if features['word_count'] > 0 else 0
    
    return features

def main():
    print("Loading and preparing data...")
    data = load_and_combine_datasets()
    
    print("\nExtracting features...")
    feature_list = []
    for idx, row in data.iterrows():
        features = extract_advanced_features(row)
        feature_list.append(features)
        if idx % 5000 == 0:
            print(f"Processed {idx} rows...")
    
    # Convert to DataFrame
    feature_df = pd.DataFrame(feature_list)
    print(f"\nFeatures extracted: {feature_df.columns.tolist()}")
    
    # Prepare data
    X = feature_df
    y = data['label']
    
    # Handle labels
    if set(y.unique()) != {0, 1}:
        le = LabelEncoder()
        y = le.fit_transform(y)
        joblib.dump(le, 'label_encoder.pkl')
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set size: {len(X_train)}")
    print(f"Test set size: {len(X_test)}")
    
    # Create pipeline with SMOTE and model
    pipeline = ImbPipeline([
        ('scaler', StandardScaler()),
        ('smote', SMOTE(random_state=42)),
        ('classifier', RandomForestClassifier(random_state=42))
    ])
    
    # Define parameter grid
    param_grid = {
        'classifier__n_estimators': [100, 200, 300],
        'classifier__max_depth': [10, 20, 30],
        'classifier__min_samples_split': [2, 5, 10],
        'classifier__min_samples_leaf': [1, 2, 4]
    }
    
    print("\nPerforming grid search with cross-validation...")
    grid_search = GridSearchCV(
        pipeline,
        param_grid,
        cv=5,
        scoring='f1_macro',
        n_jobs=-1,
        verbose=2
    )
    
    # Fit the model
    grid_search.fit(X_train, y_train)
    
    # Get best model
    best_model = grid_search.best_estimator_
    print(f"\nBest parameters: {grid_search.best_params_}")
    
    # Evaluate on test set
    y_pred = best_model.predict(X_test)
    y_pred_proba = best_model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    
    print("\nModel Performance:")
    print(f"Accuracy: {accuracy:.3f}")
    print(f"ROC-AUC: {roc_auc:.3f}")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': best_model.named_steps['classifier'].feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Save model and feature names
    joblib.dump(best_model, 'phishing_model.pkl')
    joblib.dump(X.columns.tolist(), 'feature_names.pkl')
    print("\nModel and feature names saved successfully!")
    
    # Cross-validation scores
    cv_scores = cross_val_score(best_model, X, y, cv=5, scoring='f1')
    print(f"\nCross-validation F1 scores: {cv_scores}")
    print(f"Mean CV F1 score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")

if __name__ == "__main__":
    main()