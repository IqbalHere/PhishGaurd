import sys
import pandas as pd
import traceback
from URLFeatureExtraction import featureExtraction

def analyze_url(url):
    try:
        # Extract features from URL
        print(f"Extracting features from: {url}")
        features = featureExtraction(url)
        
        # Convert features to DataFrame
        feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                         'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                         'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']
        
        feature_desc = {
            'Have_IP': 'IP address in URL',
            'Have_At': '@ symbol in URL',
            'URL_Length': 'Length of URL (>= 54 chars)',
            'URL_Depth': 'Number of sub-directories in URL',
            'Redirection': 'Redirection using "//" in URL path',
            'https_Domain': 'HTTPS token in domain part',
            'TinyURL': 'Using URL shortening services',
            'Prefix/Suffix': 'Prefix or suffix "-" in domain',
            'DNS_Record': 'DNS record not found',
            'Web_Traffic': 'Low web traffic',
            'Domain_Age': 'Domain age < 6 months',
            'Domain_End': 'Domain expiry < 6 months',
            'iFrame': 'Using iframe',
            'Mouse_Over': 'Mouse over changes status bar',
            'Right_Click': 'Right click disabled',
            'Web_Forwards': 'Website forwarding'
        }
        
        print("\nFeature Analysis Results:")
        print("=" * 60)
        print(f"{'Feature':<25} {'Value':<10} {'Description':<30}")
        print("-" * 60)
        
        phishing_indicators = 0
        total_features = len(features)
        
        for i, feature in enumerate(features):
            value = "Yes" if feature == 1 else "No"
            indicator = "⚠️" if feature == 1 else "✓"
            if feature == 1:
                phishing_indicators += 1
            print(f"{feature_names[i]:<25} {value:<10} {indicator} {feature_desc[feature_names[i]]}")
        
        print("=" * 60)
        phishing_score = (phishing_indicators / total_features) * 100
        print(f"\nSummary: {phishing_indicators} out of {total_features} features indicate potential phishing.")
        print(f"Phishing probability score: {phishing_score:.2f}%")
        
        if phishing_score > 60:
            print("\nVerdict: ⚠️ This URL shows strong indicators of being a phishing website.")
        elif phishing_score > 30:
            print("\nVerdict: ⚠️ This URL shows moderate indicators of being a phishing website.")
        else:
            print("\nVerdict: ✓ This URL appears to be legitimate.")
            
        return features
    except Exception as e:
        print(f"\nError occurred during analysis: {str(e)}")
        print("\nDetailed error information:")
        traceback.print_exc()
        return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
        analyze_url(url)
    else:
        # Use a sample URL if none provided
        sample_urls = [
            "https://www.google.com",
            "http://tiny.cc/phishingsite",
            "http://142.93.107.132/login-submit"
        ]
        
        print("No URL provided. Testing with sample URLs...\n")
        for url in sample_urls:
            print("\n" + "=" * 70)
            print(f"Analyzing URL: {url}")
            print("=" * 70)
            analyze_url(url)
            print("\n" + "=" * 70)
        
        print("\nTo analyze a specific URL, run: python feature_analyzer.py <url>") 