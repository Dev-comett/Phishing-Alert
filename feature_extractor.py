import re
from urllib.parse import urlparse

def extract_features(url):
    features = []

    # Length of the URL
    features.append(len(url))

    # Count of special characters
    features.append(url.count('@'))
    features.append(url.count('-'))
    features.append(url.count('.'))

    # HTTPS present or not
    features.append(1 if 'https' in url else 0)

    # Check if IP address is used instead of domain
    features.append(1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0)

    # Length of the path
    parsed = urlparse(url)
    features.append(len(parsed.path))

    return features
