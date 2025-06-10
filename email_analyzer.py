import pandas as pd
import joblib
import re
from email import message_from_string
from email.utils import parseaddr
from urllib.parse import urlparse

class EmailAnalyzer:
    def __init__(self):
        """Load the trained model and feature names"""
        try:
            self.model = joblib.load('phishing_model.pkl')
            self.feature_names = joblib.load('feature_names.pkl')
            print("Model loaded successfully!")
        except FileNotFoundError:
            print("Error: Model files not found. Please train the model first.")
            return None
    
    def parse_raw_email(self, raw_email):
        """Parse raw email text and extract components"""
        try:
            # Parse email using Python's email library
            msg = message_from_string(raw_email)
            
            # Extract basic components
            sender = msg.get('From', '')
            receiver = msg.get('To', '')
            subject = msg.get('Subject', '')
            date = msg.get('Date', '')
            
            # Get email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            return {
                'sender': sender,
                'receiver': receiver,
                'subject': subject,
                'date': date,
                'body': body
            }
        except Exception as e:
            print(f"Error parsing email: {e}")
            # Fallback: simple text parsing
            lines = raw_email.split('\n')
            
            sender = next((line.split(':', 1)[1].strip() for line in lines if line.startswith('From:')), '')
            receiver = next((line.split(':', 1)[1].strip() for line in lines if line.startswith('To:')), '')
            subject = next((line.split(':', 1)[1].strip() for line in lines if line.startswith('Subject:')), '')
            
            # Everything after first empty line is body
            body_start = raw_email.find('\n\n')
            body = raw_email[body_start:].strip() if body_start != -1 else ''
            
            return {
                'sender': sender,
                'receiver': receiver,
                'subject': subject,
                'date': '',
                'body': body
            }
    
    def extract_features_from_email(self, email_data):
        """Extract the same features used in training"""
        sender = str(email_data['sender']) if email_data['sender'] else ''
        body = str(email_data['body']) if email_data['body'] else ''
        subject = str(email_data['subject']) if email_data['subject'] else ''
        
        features = {}
        
        # Sender features
        features['sender_length'] = len(sender)
        features['sender_has_numbers'] = 1 if re.search(r'\d', sender) else 0
        features['sender_suspicious_tld'] = 1 if any(tld in sender.lower() for tld in ['.tk', '.ml', '.cf', '.ga', '.pw', '.xyz', '.top', '.work', '.click', '.info', '.biz', '.online', '.site', '.website']) else 0
        
        # Extract domain from sender
        if '@' in sender:
            domain = sender.split('@')[-1].split('>')[0].strip()
            features['sender_domain_length'] = len(domain)
            features['sender_common_domain'] = 1 if any(common in domain.lower() for common in ['gmail', 'yahoo', 'hotmail', 'outlook', 'protonmail', 'icloud']) else 0
            # Check for brand impersonation
            features['brand_impersonation'] = 1 if any(brand in domain.lower() for brand in ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'ebay', 'linkedin']) else 0
        else:
            features['sender_domain_length'] = 0
            features['sender_common_domain'] = 0
            features['brand_impersonation'] = 0
        
        # URL features from body and subject
        full_text = body + ' ' + subject
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls_found = re.findall(url_pattern, full_text)
        
        features['has_urls'] = 1 if len(urls_found) > 0 else 0
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
        
        # Enhanced content analysis
        urgency_words = [
            'urgent', 'immediate', 'asap', 'important', 'action required',
            'verify now', 'suspended', 'blocked', 'expire', 'limited time',
            'last chance', 'final notice', 'immediately', 'right now',
            'today only', 'expiring soon', 'act now', 'don\'t delay',
            'time sensitive', 'critical', 'emergency'
        ]
        features['urgency_words'] = sum(1 for word in urgency_words if word in full_text.lower())
        
        # Enhanced threat analysis
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
        
        # Enhanced brand name analysis
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
        # Check for suspicious email formatting
        features['suspicious_formatting'] = 1 if (
            re.search(r'[A-Z]{3,}', subject) or  # ALL CAPS in subject
            re.search(r'[!]{2,}', subject) or    # Multiple exclamation marks
            re.search(r'[?]{2,}', subject) or    # Multiple question marks
            len(subject.split()) > 15            # Very long subject
        ) else 0
        
        # Check for suspicious email patterns
        features['suspicious_patterns'] = 1 if (
            re.search(r'\b(?:click|verify|confirm|update|login|password)\b.*\b(?:now|immediately|urgently|asap)\b', full_text.lower()) or
            re.search(r'\b(?:account|security|verification)\b.*\b(?:required|needed|mandatory)\b', full_text.lower()) or
            re.search(r'\b(?:suspended|blocked|locked|terminated)\b.*\b(?:account|access|service)\b', full_text.lower())
        ) else 0
        
        return features
    
    def analyze_email(self, raw_email):
        """Main function to analyze an email"""
        
        # Step 1: Parse the raw email
        email_data = self.parse_raw_email(raw_email)
        
        # Step 2: Extract features
        features = self.extract_features_from_email(email_data)
        
        # Step 3: Convert to DataFrame with correct feature order
        feature_df = pd.DataFrame([features])
        
        # Ensure features are in the same order as training
        feature_df = feature_df.reindex(columns=self.feature_names, fill_value=0)
        
        # Step 4: Make prediction
        prediction = self.model.predict(feature_df)[0]
        probabilities = self.model.predict_proba(feature_df)[0]
        
        # Step 5: Calculate risk score with feature weights
        base_risk = int(probabilities[1] * 100)  # Base probability of being malicious
        
        # Updated feature weights for risk calculation
        feature_weights = {
            'sender_suspicious_tld': 15,
            'brand_impersonation': 20,
            'domain_mismatch': 25,
            'urgency_words': 3,  # per word
            'threat_words': 4,   # per word
            'has_grammar_errors': 8,
            'suspicious_url_patterns': 8,  # per pattern
            'has_urls': 3,
            'suspicious_formatting': 10,
            'suspicious_patterns': 15,
            'url_domain_count': 2,  # per domain
            'suspicious_url_domains': 5  # per suspicious domain
        }
        
        # Calculate additional risk from features
        additional_risk = 0
        for feature, weight in feature_weights.items():
            if feature in features:
                if feature in ['urgency_words', 'threat_words', 'suspicious_url_patterns', 'url_domain_count', 'suspicious_url_domains']:
                    additional_risk += min(features[feature] * weight, weight * 3)  # Cap the multiplier effect
                else:
                    additional_risk += features[feature] * weight
        
        # Calculate total risk score with improved logic
        if base_risk < 30 and additional_risk < 40:  # Increased threshold
            risk_score = base_risk
        else:
            # Weight the base risk more heavily when it's high
            if base_risk > 70:
                risk_score = int(base_risk * 0.7 + additional_risk * 0.3)
            else:
                risk_score = int(base_risk * 0.5 + additional_risk * 0.5)
            
            # Ensure risk score doesn't exceed 100
            risk_score = min(100, risk_score)
        
        # Step 6: Determine category and recommendation with more granular thresholds
        if risk_score >= 75:
            category = "CRITICAL RISK - Highly Likely Phishing"
            recommendation = "🚨 IMMEDIATE ACTION REQUIRED: Do not interact with this email. Delete it immediately and report as phishing."
        elif risk_score >= 60:
            category = "HIGH RISK - Likely Phishing/Spam"
            recommendation = "⚠️ Do not click any links or download attachments. Delete this email."
        elif risk_score >= 40:
            category = "MEDIUM RISK - Suspicious"
            recommendation = "⚡ Be cautious. Verify sender identity before taking any action."
        elif risk_score >= 20:
            category = "LOW RISK - Potentially Suspicious"
            recommendation = "🔍 Exercise caution. Review the email carefully before taking any action."
        else:
            category = "MINIMAL RISK - Appears Safe"
            recommendation = "✅ Email appears legitimate, but always stay vigilant."
        
        # Step 7: Return detailed analysis
        return {
            'risk_score': risk_score,
            'category': category,
            'recommendation': recommendation,
            'is_malicious': prediction == 1,
            'confidence': max(probabilities),
            'email_details': {
                'sender': email_data['sender'],
                'subject': email_data['subject'],
                'has_urls': features['has_urls'],
                'url_count': features['num_urls']
            },
            'features_detected': features,
            'base_risk': base_risk,
            'additional_risk': additional_risk,
            'feature_weights': feature_weights
        }

# Test function
def test_analyzer():
    """Test the analyzer with sample emails"""
    
    analyzer = EmailAnalyzer()
    
    # Test email 1: Suspicious phishing email
    phishing_email = """From: security-alert@paypal-verify.tk
To: user@example.com
Subject: URGENT: Your PayPal Account Will Be Suspended
Date: Mon, 1 Jan 2024 10:00:00 +0000

Your PayPal account has been temporarily suspended due to suspicious activity.

Click here immediately to verify your account: http://paypal-verify.tk/urgent-verify
You have 24 hours to complete verification or your account will be permanently closed.

Act now to avoid losing access to your funds!

PayPal Security Team
"""

    # Test email 2: Legitimate email
    legitimate_email = """From: notifications@github.com
To: developer@company.com
Subject: Pull request merged in your repository
Date: Mon, 1 Jan 2024 15:30:00 +0000

Your pull request #123 has been successfully merged into the main branch.

Repository: myproject/backend
Merged by: teammate@company.com

View the changes: https://github.com/myproject/backend/pull/123

Best regards,
GitHub Team
"""

    print("=== ANALYZING SUSPICIOUS EMAIL ===")
    result1 = analyzer.analyze_email(phishing_email)
    print_analysis_result(result1)
    
    print("\n" + "="*50 + "\n")
    
    print("=== ANALYZING LEGITIMATE EMAIL ===")
    result2 = analyzer.analyze_email(legitimate_email)
    print_analysis_result(result2)

def print_analysis_result(result):
    """Pretty print the analysis result"""
    print(f"🎯 RISK SCORE: {result['risk_score']}%")
    print(f"📊 CATEGORY: {result['category']}")
    print(f"💡 RECOMMENDATION: {result['recommendation']}")
    print(f"🔍 CONFIDENCE: {result['confidence']:.2f}")
    
    print(f"\n📧 EMAIL DETAILS:")
    print(f"   Sender: {result['email_details']['sender']}")
    print(f"   Subject: {result['email_details']['subject']}")
    print(f"   Contains URLs: {'Yes' if result['email_details']['has_urls'] else 'No'}")
    print(f"   URL Count: {result['email_details']['url_count']}")
    
    print(f"\n🔧 TECHNICAL FEATURES:")
    for feature, value in result['features_detected'].items():
        print(f"   {feature}: {value}")

if __name__ == "__main__":
    test_analyzer()