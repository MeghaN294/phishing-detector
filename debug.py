from detector import PhishingDetector

det = PhishingDetector()
print("Model classes:", det.model.classes_)
print()

for url in [
    "https://www.google.com",
    "https://www.getbeamer.com",
    "https://www.python.org",
    "https://stackoverflow.com",
    "http://gogle.com",
    "http://secure-login-paypal.com",
    "http://91.219.171.20:37006/i",
]:
    features = det.extract_all_features(url)
    feature_values = [features.get(n, 0) for n in det.feature_names]

    import numpy as np
    X = np.array([feature_values])
    X_scaled = det.scaler.transform(X)
    X_sel = det.feature_selector.transform(X_scaled)

    prob = det.model.predict_proba(X_sel)[0]
    pred = det.model.predict(X_sel)[0]

    classes = list(det.model.classes_)
    phish_idx = classes.index(1) if 1 in classes else 0

    print(f"{url}")
    print(f"  ML prediction: {pred}  |  proba: {prob}  |  phishing_prob: {prob[phish_idx]:.3f}")
    print()