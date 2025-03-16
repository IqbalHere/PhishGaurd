import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import pandas as pd
import traceback
import re
import socket
import ssl
import urllib.parse
import numpy as np
from datetime import datetime
import io
import contextlib
from urllib3.exceptions import NameResolutionError
# Import ML libraries
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Create a suppressed version of the feature extraction
# This wraps the original function to suppress error output
original_stderr = sys.stderr
original_stdout = sys.stdout

# Import the feature extraction module with output suppression
null_output = open(os.devnull, 'w')
sys.stderr = null_output
sys.stdout = null_output
from URLFeatureExtraction import featureExtraction as original_featureExtraction
sys.stderr = original_stderr
sys.stdout = original_stdout

# Create wrapper function to suppress errors
def safe_feature_extraction(url):
    """Wrapper for featureExtraction that suppresses console output"""
    with contextlib.redirect_stderr(io.StringIO()):
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                return original_featureExtraction(url)
            except Exception as e:
                print(f"Feature extraction error (suppressed from UI): {str(e)}")
                # Return a default set of features (all suspicious)
                return [1, 1, 1, 5, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0]

class PhishGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        self.setup_ui()
        self.history = []
        
        # Define feature weights (higher = more important)
        self.feature_weights = {
            'Have_IP': 0.9,        # Strong indicator
            'Have_At': 0.8,        # Strong indicator
            'URL_Length': 0.4,     # Moderate indicator
            'URL_Depth': 0.3,      # Weak indicator
            'Redirection': 0.7,    # Strong indicator
            'https_Domain': 0.7,   # Strong indicator
            'TinyURL': 0.6,        # Moderate indicator
            'Prefix/Suffix': 0.5,  # Moderate indicator
            'DNS_Record': 0.8,     # Strong indicator
            'Web_Traffic': 0.4,    # Moderate indicator
            'Domain_Age': 0.6,     # Moderate indicator
            'Domain_End': 0.3,     # Weak indicator
            'iFrame': 0.7,         # Strong indicator
            'Mouse_Over': 0.6,     # Moderate indicator
            'Right_Click': 0.5,    # Moderate indicator
            'Web_Forwards': 0.5    # Moderate indicator
        }
        
        # Common brands that are often targeted in phishing
        self.common_targets = [
            'paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook', 
            'instagram', 'netflix', 'gmail', 'bank', 'chase', 'wellsfargo', 
            'amex', 'visa', 'mastercard', 'discover', 'linkedin', 'twitter', 
            'yahoo', 'ebay', 'dropbox', 'icloud', 'outlook', 'office365'
        ]
        
        # Top level domains frequently used in phishing
        self.suspicious_tlds = [
            '.xyz', '.top', '.win', '.loan', '.work', '.click', '.link', 
            '.review', '.country', '.party', '.stream', '.gq', '.ml', '.cf', 
            '.tk', '.ga', '.icu', '.online'
        ]
        
        # Initialize or load ML model
        self.ml_model = self.initialize_ml_model()
        
    def initialize_ml_model(self):
        """Initialize or load a machine learning model for phishing detection"""
        model_path = 'phishguard_model.joblib'
        
        # Check if model already exists
        if os.path.exists(model_path):
            try:
                # Load existing model
                return joblib.load(model_path)
            except:
                # If loading fails, create a new model
                pass
        
        # Create and train a new model if needed
        # Using RandomForestClassifier as it's effective for this type of classification
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Train with some initial default data if available
        # This is a simplified approach - in a real system, you'd train with a large dataset
        try:
            # Example data structure:
            # X_train is a matrix of features (the 16 URL features)
            # y_train is a vector of labels (1 for phishing, 0 for legitimate)
            
            # Generate some synthetic training data based on common patterns
            # This is very simplified - a real model would use thousands of examples
            X_train = np.array([
                # Legitimate examples (0)
                [0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],  # google.com
                [0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],  # microsoft.com
                [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],  # apple.com
                [0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # amazon.com
                [0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],  # facebook.com
                # Phishing examples (1)
                [1, 0, 1, 4, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1],  # IP-based phishing
                [0, 1, 1, 3, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0],  # @-based phishing
                [0, 0, 1, 5, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1],  # Long complex phishing
                [0, 0, 1, 2, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0],  # Brand-based phishing
                [0, 0, 0, 3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1],  # TinyURL phishing
            ])
            
            y_train = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
            
            # Train the model
            model.fit(X_train, y_train)
            
            # Save the model for future use
            joblib.dump(model, model_path)
            
            return model
        
        except Exception as e:
            print(f"Error training ML model: {str(e)}")
            # Return a basic model even if training fails
            return RandomForestClassifier(n_estimators=100, random_state=42)
        
    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # URL input section
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(url_frame, text="Enter URL:").pack(side=tk.LEFT, padx=5)
        
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=50)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.url_entry.bind("<Return>", lambda event: self.analyze_button_click())
        
        self.analyze_button = ttk.Button(url_frame, text="Analyze", command=self.analyze_button_click)
        self.analyze_button.pack(side=tk.LEFT, padx=5)
        
        # Add some sample URLs
        samples_frame = ttk.Frame(main_frame)
        samples_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(samples_frame, text="Sample URLs:").pack(side=tk.LEFT, padx=5)
        
        sample_urls = [
            "https://www.google.com",
            "https://paypal-secure-login.com/verification",
            "https://amaz0n-secure.com/signin"
        ]
        
        for url in sample_urls:
            btn = ttk.Button(samples_frame, text=url, 
                            command=lambda u=url: self.set_sample_url(u))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Create notebook for results and history
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Results tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="Analysis Results")
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initial results view
        self.create_results_view()
        
        # History tab
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="History")
        
        self.history_text = scrolledtext.ScrolledText(history_frame, wrap=tk.WORD)
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.history_text.config(state=tk.DISABLED)
        
    def create_results_view(self):
        # Clear previous widgets
        for widget in self.results_frame.winfo_children():
            widget.destroy()
            
        # Create scrollable text widget for results
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.insert(tk.END, "Enter a URL and click 'Analyze' to check for phishing indicators.")
        self.results_text.config(state=tk.DISABLED)
        
    def set_sample_url(self, url):
        self.url_var.set(url)
        
    def analyze_button_click(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to analyze.")
            return
        
        # Validate and normalize URL
        try:
            url = self.normalize_url(url)
        except Exception as e:
            messagebox.showerror("Invalid URL", f"Please enter a valid URL.\nError: {str(e)}")
            return
            
        # Disable the analyze button and show status
        self.analyze_button.config(state=tk.DISABLED)
        self.status_var.set(f"Analyzing {url}...")
        self.root.update_idletasks()
        
        # Run analysis in a separate thread to keep UI responsive
        threading.Thread(target=self.analyze_url_thread, args=(url,), daemon=True).start()
    
    def normalize_url(self, url):
        """Normalize URL by adding protocol if missing, handling encoding, etc."""
        # Add http:// if no protocol specified
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        # Parse URL to handle encoding, etc.
        parsed = urllib.parse.urlparse(url)
        
        # Validate basic URL components
        if not parsed.netloc:
            raise ValueError("Invalid URL: missing domain")
        
        # Normalize domain (lowercase)
        normalized = parsed._replace(netloc=parsed.netloc.lower())
        return urllib.parse.urlunparse(normalized)
    
    def verify_domain_exists(self, domain):
        """Check if a domain exists by attempting to resolve it, suppressing console errors"""
        # Redirect stderr to capture and suppress DNS-related error messages
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        
        try:
            socket.gethostbyname(domain)
            domain_exists = True
        except:
            domain_exists = False
        finally:
            # Restore stderr
            sys.stderr = old_stderr
            
        return domain_exists
        
    def analyze_url_thread(self, url):
        try:
            # Use our safe wrapper for feature extraction to avoid console errors
            features = safe_feature_extraction(url)
            
            # Add additional checks
            additional_features = self.additional_checks(url)
            
            # Define feature names and descriptions
            feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                            'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                            'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']
            
            # Add additional feature names
            additional_feature_names = list(additional_features.keys())
            all_feature_names = feature_names + additional_feature_names
            
            # Combine all features
            all_features = features + [additional_features[name] for name in additional_feature_names]
            
            # Get ML model prediction
            ml_prediction, ml_confidence = self.get_ml_prediction(features)
            
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
                'Web_Forwards': 'Website forwarding',
                'Brand_Squatting': 'Domain contains popular brand name',
                'Character_Substitution': 'Contains lookalike character substitution',
                'Suspicious_TLD': 'Uses suspicious top-level domain',
                'URL_Entropy': 'High randomness in URL structure',
                'SSL_Validity': 'Invalid or missing SSL certificate',
                'Domain_Typo': 'Possible typosquatting domain'
            }
            
            # Update weights for additional features
            additional_weights = {
                'Brand_Squatting': 0.9,
                'Character_Substitution': 0.8,
                'Suspicious_TLD': 0.7,
                'URL_Entropy': 0.6,
                'SSL_Validity': 0.8,
                'Domain_Typo': 0.7
            }
            self.feature_weights.update(additional_weights)
            
            # Calculate weighted phishing score
            weighted_score = self.calculate_weighted_score(all_feature_names, all_features)
            
            # Simple count of indicators for display
            phishing_indicators = sum(all_features)
            total_features = len(all_features)
            simple_score = (phishing_indicators / total_features) * 100
            
            # Combined score - weighted blend of rule-based and ML scores
            if ml_confidence >= 0.7:  # If ML model is confident, give it more weight
                combined_score = (weighted_score * 0.4) + (ml_prediction * 100 * 0.6)
            else:
                combined_score = (weighted_score * 0.7) + (ml_prediction * 100 * 0.3)
            
            # Prepare result text
            result_text = f"Analysis Results for: {url}\n\n"
            
            # Add ML verdict at the top with prominent styling
            ml_verdict = "PHISHING" if ml_prediction == 1 else "LEGITIMATE"
            ml_confidence_pct = ml_confidence * 100
            
            result_text += "=" * 60 + "\n"
            result_text += f"MACHINE LEARNING VERDICT: {ml_verdict}\n"
            result_text += f"Confidence: {ml_confidence_pct:.2f}%\n"
            result_text += "=" * 60 + "\n\n"
            
            # Add domain verification status
            domain = urllib.parse.urlparse(url).netloc
            domain_exists = self.verify_domain_exists(domain)
            result_text += f"Domain status: {'Exists' if domain_exists else 'Does not exist (Suspicious)'}\n\n"
            
            # Add feature breakdown
            result_text += "FEATURE ANALYSIS:\n"
            result_text += "-" * 60 + "\n"
            result_text += f"{'Feature':<25} {'Value':<10} {'Description':<30}\n"
            result_text += "-" * 60 + "\n"
            
            # Add original features
            for i, feature in enumerate(features):
                value = "Yes" if feature == 1 else "No"
                indicator = "⚠️" if feature == 1 else "✓"
                weight = self.feature_weights.get(feature_names[i], 0.5)
                importance = "High" if weight >= 0.7 else "Medium" if weight >= 0.5 else "Low"
                result_text += f"{feature_names[i]:<25} {value:<10} {indicator} {feature_desc[feature_names[i]]} ({importance})\n"
            
            # Add additional features
            for i, name in enumerate(additional_feature_names):
                value = "Yes" if additional_features[name] == 1 else "No"
                indicator = "⚠️" if additional_features[name] == 1 else "✓"
                weight = self.feature_weights.get(name, 0.5)
                importance = "High" if weight >= 0.7 else "Medium" if weight >= 0.5 else "Low"
                result_text += f"{name:<25} {value:<10} {indicator} {feature_desc[name]} ({importance})\n"
            
            result_text += "=" * 60 + "\n\n"
            result_text += f"Summary: {phishing_indicators} out of {total_features} features indicate potential phishing.\n"
            result_text += f"Rule-Based Score: {weighted_score:.2f}%\n"
            result_text += f"ML-Based Score: {ml_prediction * 100:.2f}% (Confidence: {ml_confidence_pct:.2f}%)\n"
            result_text += f"Combined Score: {combined_score:.2f}%\n\n"
            
            # Improved verdict logic based on combined score
            if combined_score > 70:
                result_text += "FINAL VERDICT: ⚠️ HIGH RISK - This URL shows strong indicators of being a phishing website.\n"
                verdict = "High Risk"
            elif combined_score > 40:
                result_text += "FINAL VERDICT: ⚠️ MODERATE RISK - This URL shows moderate indicators of being a phishing website.\n"
                verdict = "Moderate Risk"
            elif combined_score > 20:
                result_text += "FINAL VERDICT: ⚠️ LOW RISK - This URL shows some suspicious indicators but may be legitimate.\n"
                verdict = "Low Risk"
            else:
                result_text += "FINAL VERDICT: ✓ SAFE - This URL appears to be legitimate.\n"
                verdict = "Safe"
            
            # Add to history
            self.add_to_history(url, verdict, combined_score)
            
            # Update UI on the main thread
            self.root.after(0, self.update_results, result_text)
            
        except Exception as e:
            error_text = f"Error analyzing {url}:\n{str(e)}\n\n"
            error_text += traceback.format_exc()
            self.root.after(0, self.update_results, error_text)
        
        # Re-enable analyze button
        self.root.after(0, self.enable_analyze_button)
    
    def get_ml_prediction(self, features):
        """Get prediction from the ML model"""
        try:
            # Convert features to the format expected by the model
            features_array = np.array(features).reshape(1, -1)
            
            # Get prediction
            prediction = self.ml_model.predict(features_array)[0]
            
            # Get prediction probability
            proba = self.ml_model.predict_proba(features_array)[0]
            confidence = proba[1] if prediction == 1 else proba[0]
            
            return prediction, confidence
            
        except Exception as e:
            print(f"ML prediction error: {str(e)}")
            # Return a default value if prediction fails
            return 0, 0.5
    
    def calculate_weighted_score(self, feature_names, features):
        """Calculate a weighted phishing score based on feature importance"""
        total_weight = 0
        weighted_sum = 0
        
        for i, feature in enumerate(features):
            weight = self.feature_weights.get(feature_names[i], 0.5)  # Default weight of 0.5
            weighted_sum += feature * weight
            total_weight += weight
        
        # Normalize to percentage
        if total_weight > 0:
            return (weighted_sum / total_weight) * 100
        return 0
    
    def additional_checks(self, url):
        """Perform additional sophisticated checks on the URL"""
        results = {}
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # 1. Brand name squatting detection
        brand_squatting = 0
        for brand in self.common_targets:
            if brand in domain and brand != domain:
                brand_squatting = 1
                break
        results['Brand_Squatting'] = brand_squatting
        
        # 2. Character substitution detection (e.g., 'paypaI' with capital I instead of lowercase l)
        char_substitution = 0
        substitution_patterns = [
            (r'paypa[l1!i]', 'paypal'),
            (r'g[o0]og[l1!i]e', 'google'),
            (r'amaz[o0]n', 'amazon'),
            (r'faceb[o0][o0]k', 'facebook'),
            (r'm[i1!]cr[o0]s[o0]ft', 'microsoft')
        ]
        
        for pattern, _ in substitution_patterns:
            if re.search(pattern, domain, re.IGNORECASE) and not re.search(pattern.replace('[', '').replace(']', ''), domain, re.IGNORECASE):
                char_substitution = 1
                break
        
        results['Character_Substitution'] = char_substitution
        
        # 3. Suspicious TLD check
        suspicious_tld = 0
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                suspicious_tld = 1
                break
        results['Suspicious_TLD'] = suspicious_tld
        
        # 4. URL entropy (randomness measurement)
        # High entropy often indicates randomly generated phishing domains
        url_entropy = 0
        
        # Calculate character frequency
        char_freq = {}
        for char in domain:
            if char in char_freq:
                char_freq[char] += 1
            else:
                char_freq[char] = 1
        
        # Calculate entropy
        domain_length = len(domain)
        entropy = 0
        for char, freq in char_freq.items():
            prob = freq / domain_length
            entropy -= prob * (math.log(prob, 2) if prob > 0 else 0)
        
        # URLs with entropy > 4 are often randomly generated
        if entropy > 4 and domain_length > 10:
            url_entropy = 1
        
        results['URL_Entropy'] = url_entropy
        
        # 5. SSL certificate check - using a context manager to suppress errors
        ssl_valid = 0
        if url.startswith('https://'):
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    ssl_valid = 0  # Assume invalid until proven otherwise
                    hostname = domain
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=3) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            # Check if certificate is valid
                            if cert and 'subjectAltName' in cert:
                                ssl_valid = 0  # Valid certificate
            except:
                ssl_valid = 1  # Invalid or problem with certificate
        
        results['SSL_Validity'] = ssl_valid
        
        # 6. Domain typo detection (typosquatting)
        domain_typo = 0
        common_domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com']
        
        # Check for common typosquatting patterns
        for common_domain in common_domains:
            # Calculate Levenshtein distance
            distance = self.levenshtein_distance(domain, common_domain)
            # If very similar but not identical
            if 0 < distance <= 2:
                domain_typo = 1
                break
                
        results['Domain_Typo'] = domain_typo
        
        return results
    
    def levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]
        
    def update_results(self, text):
        # Clear and update results text
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, text)
        self.results_text.config(state=tk.DISABLED)
        
        # Switch to results tab
        self.notebook.select(0)
        
        # Update status
        self.status_var.set("Analysis complete")
        
    def add_to_history(self, url, verdict, score):
        # Add to history list
        timestamp = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        history_entry = f"[{timestamp}] {url} - {verdict} ({score:.2f}%)\n"
        self.history.append(history_entry)
        
        # Update history text
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete(1.0, tk.END)
        for entry in reversed(self.history):  # Show most recent first
            self.history_text.insert(tk.END, entry)
        self.history_text.config(state=tk.DISABLED)
        
    def enable_analyze_button(self):
        self.analyze_button.config(state=tk.NORMAL)
        self.status_var.set("Ready")
        
if __name__ == "__main__":
    # Import math here since it's only needed for the entropy calculation
    import math
    
    root = tk.Tk()
    app = PhishGuardApp(root)
    root.mainloop() 