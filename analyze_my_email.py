from email_analyzer import EmailAnalyzer

def analyze_custom_email():
    """Analyze your own email"""
    
    # Initialize analyzer
    analyzer = EmailAnalyzer()
    
    print("=== EMAIL PHISHING DETECTOR ===")
    print("Paste your raw email below (press Enter twice when done):")
    
    # Get email input from user
    lines = []
    while True:
        line = input()
        if line == "" and len(lines) > 0 and lines[-1] == "":
            break
        lines.append(line)
    
    raw_email = '\n'.join(lines)
    
    if not raw_email.strip():
        print("No email provided!")
        return
    
    print("\n" + "="*50)
    print("ANALYZING EMAIL...")
    print("="*50)
    
    # Analyze the email
    result = analyzer.analyze_email(raw_email)
    
    # Display results
    print(f"\n🎯 RISK SCORE: {result['risk_score']}%")
    print(f"   - Base Risk (from model): {result['base_risk']}%")
    print(f"   - Additional Risk (from features): {result['additional_risk']}%")
    print(f"📊 CATEGORY: {result['category']}")
    print(f"💡 RECOMMENDATION: {result['recommendation']}")
    print(f"🔍 CONFIDENCE: {result['confidence']:.2f}")
    
    if result['risk_score'] >= 60:
        print("\n🚨 WARNING: This email shows high risk indicators!")
    elif result['risk_score'] >= 30:
        print("\n⚠️ CAUTION: This email has some suspicious elements.")
    else:
        print("\n✅ This email appears to be safe.")
    
    print(f"\n📧 EMAIL DETAILS:")
    print(f"   Sender: {result['email_details']['sender']}")
    print(f"   Subject: {result['email_details']['subject']}")
    print(f"   Contains URLs: {'Yes' if result['email_details']['has_urls'] else 'No'}")
    print(f"   URL Count: {result['email_details']['url_count']}")
    
    print(f"\n🔧 DETECTED FEATURES:")
    features = result['features_detected']
    weights = result['feature_weights']
    
    print("   Sender Analysis:")
    print(f"      - Length: {features['sender_length']}")
    print(f"      - Contains Numbers: {'Yes' if features['sender_has_numbers'] else 'No'}")
    print(f"      - Suspicious TLD: {'Yes' if features['sender_suspicious_tld'] else 'No'} (Weight: {weights['sender_suspicious_tld']}%)")
    print(f"      - Domain Length: {features['sender_domain_length']}")
    print(f"      - Common Domain: {'Yes' if features['sender_common_domain'] else 'No'}")
    print(f"      - Brand Impersonation: {'Yes' if features['brand_impersonation'] else 'No'} (Weight: {weights['brand_impersonation']}%)")
    
    print("\n   Content Analysis:")
    print(f"      - Urgency Words: {features['urgency_words']} (Weight: {weights['urgency_words']}% per word)")
    print(f"      - Threat Words: {features['threat_words']} (Weight: {weights['threat_words']}% per word)")
    print(f"      - Grammar Errors: {'Yes' if features['has_grammar_errors'] else 'No'} (Weight: {weights['has_grammar_errors']}%)")
    print(f"      - Brand Mentions: {features['brand_mentions']}")
    print(f"      - Domain Mismatch: {'Yes' if features['domain_mismatch'] else 'No'} (Weight: {weights['domain_mismatch']}%)")
    
    print("\n   URL Analysis:")
    print(f"      - Has URLs: {'Yes' if features['has_urls'] else 'No'} (Weight: {weights['has_urls']}%)")
    print(f"      - Number of URLs: {features['num_urls']}")
    print(f"      - URL Domain Count: {features['url_domain_count']} (Weight: {weights['url_domain_count']}% per domain)")
    print(f"      - Suspicious URL Domains: {features['suspicious_url_domains']} (Weight: {weights['suspicious_url_domains']}% per suspicious domain)")
    print(f"      - Suspicious URL Patterns: {features['suspicious_url_patterns']} (Weight: {weights['suspicious_url_patterns']}% per pattern)")
    
    # Ask if user wants to analyze another email
    print("\nWould you like to analyze another email? (y/n): ", end="")
    if input().lower().startswith('y'):
        analyze_custom_email()

if __name__ == "__main__":
    analyze_custom_email()