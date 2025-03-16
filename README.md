# PhishGuard

PhishGuard is a powerful GUI application designed to detect phishing websites by analyzing URLs for suspicious patterns and characteristics. Using a combination of advanced detection algorithms, a weighted scoring system, and machine learning, PhishGuard provides a comprehensive assessment of URL safety.

## Features

- **Intuitive GUI Interface**: Easy-to-use interface for URL analysis
- **Machine Learning Detection**: Uses a RandomForest classifier model to provide accurate phishing verdicts
- **Weighted Scoring System**: More accurate detection with feature importance weighting
- **Combined Intelligence**: Integrates rule-based analysis with machine learning for better results
- **Advanced Detection Techniques**:
  - Brand name squatting detection
  - Character substitution analysis
  - Suspicious TLD checking
  - URL entropy calculation
  - SSL certificate validation
  - Domain typosquatting detection
- **Detailed Results**: Comprehensive breakdown of each analyzed feature with importance ranking
- **Confidence Metrics**: Shows confidence level of machine learning predictions
- **Risk Classification**: Four-level risk assessment (Safe, Low Risk, Moderate Risk, High Risk)
- **Analysis History**: Track all previously analyzed URLs with timestamps and verdicts
- **Sample URLs**: Built-in sample URLs for testing the application

## Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - tkinter (usually comes with Python)
  - pandas
  - beautifulsoup4
  - requests
  - socket
  - ssl
  - re
  - whois (may require additional installation on some systems)
  - numpy
  - scikit-learn
  - joblib

## Installation

1. Clone this repository or download the source code
2. Install required packages:
   ```
   pip install pandas beautifulsoup4 requests python-whois numpy scikit-learn joblib
   ```

## Usage

1. Open a terminal/command prompt in the project directory
2. Run the PhishGuard application:
   ```
   python phishguard.py
   ```
3. Enter a URL in the input field or select one of the sample URLs
4. Click "Analyze" to perform the analysis
5. View the detailed results showing:
   - Machine learning verdict with confidence level
   - All detected features and their importance
   - Rule-based, ML-based, and combined scores
6. Check the History tab to review previously analyzed URLs

## How It Works

PhishGuard combines machine learning with rule-based detection:

### Machine Learning Detection
- Uses a RandomForest classifier trained on phishing and legitimate URL features
- Provides a binary classification (Phishing or Legitimate) with confidence score
- Automatically improves with more data
- Adapts to new phishing techniques

### Standard Features
- Presence of IP addresses in the URL
- Presence of @ symbol in the URL
- URL length analysis
- URL depth (number of subdirectories)
- Redirection checks
- HTTPS token in domain part
- TinyURL service detection
- Prefix/suffix analysis
- DNS record verification
- Web traffic analysis
- Domain age and expiration checks
- iFrame, mouse over, and right-click disable detection
- Website forwarding analysis

### Advanced Features
- Brand name squatting detection for 24 commonly targeted brands
- Character substitution detection (e.g., amaz0n with a zero instead of o)
- Suspicious TLD detection for domains using commonly abused extensions
- URL entropy calculation to detect randomly generated domains
- SSL certificate validation
- Domain typosquatting detection using string distance algorithms

### Combined Verdict System
The final verdict is generated by combining:
- The weighted rule-based score
- The machine learning prediction and confidence
- Weighted blending based on ML confidence levels

### Scoring System
Each feature is assigned a weight based on its importance in identifying phishing:
- High importance features (weight 0.7-0.9): IP in URL, brand squatting, etc.
- Medium importance features (weight 0.5-0.6): TinyURL, right-click disabled, etc.
- Low importance features (weight 0.3-0.4): URL length, domain expiration, etc.

## Command Line Alternative

For users who prefer command-line tools, the feature_analyzer.py script offers similar functionality without the GUI.

## Troubleshooting

- **ML Model Training**: If you encounter issues with the machine learning model, the application will fall back to rule-based detection.
- **SSL Certificate Errors**: Some legitimate websites may have certificate issues. Consider the overall score and other features.
- **Domain Age Information**: Domain age verification depends on whois database access, which may be limited for some domains.
- **False Positives**: Some legitimate websites may use techniques that trigger warnings. Use judgment in conjunction with the tool's analysis.

## License

PhishGuard is open source and available under the MIT License.

## Acknowledgements

This tool builds upon research in phishing detection techniques and machine learning methods for URL analysis. 