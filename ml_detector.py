import numpy as np
import math
from sklearn.ensemble import IsolationForest
import pickle
import os


class ThreatDetector:
    """
    Threat detection engine using scikit-learn IsolationForest to identify
    anomalous and potentially malicious files based on heuristic and statistical features.
    """

    def __init__(self, model_path: str = 'threat_model.pkl'):
        self.model_path = model_path
        self.model = None
        self._load_or_train()

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data (range: 0 to 8 bits).
        Higher entropy indicates high randomness (e.g. encrypted payloads, packed shellcode).
        """
        if not data:
            return 0.0

        length = len(data)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p_x = count / length
                entropy -= p_x * math.log(p_x, 2)

        return float(entropy)

    def _extract_features(self, file_data: bytes, filename: str) -> np.ndarray:
        """
        Extract 5 heuristic security features from file data and filename:
          1. File size in MB (capped at 10)
          2. Shannon entropy normalized to 0-1 (entropy / 8.0)
          3. Extension match score (1.0 if extension matches content, else 0.5)
          4. Printable character ratio
          5. Suspicious pattern ratio (proportion of high-entropy blocks)
        """
        if isinstance(file_data, str):
            file_data = file_data.encode('utf-8')
        elif not isinstance(file_data, (bytes, bytearray)):
            file_data = bytes(file_data)

        file_len = len(file_data)

        # 1. File size in MB (capped at 10)
        file_size_mb = min(file_len / 1_000_000, 10.0)

        # 2. Entropy normalized to 0-1
        raw_entropy = self._calculate_entropy(file_data)
        normalized_entropy = min(max(raw_entropy / 8.0, 0.0), 1.0)

        # 3. Extension match score (1.0 if extension matches content, else 0.5)
        ext = os.path.splitext(filename.lower())[1]
        ext_score = 0.5
        if ext in ('.txt', '.log', '.csv', '.json', '.xml', '.py', '.html', '.md'):
            # Text files should consist predominantly of printable text / whitespace
            printable_count = sum(1 for b in file_data if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = (printable_count / file_len) if file_len > 0 else 1.0
            if ratio >= 0.70:
                ext_score = 1.0
        elif ext == '.pdf':
            if file_data.startswith(b'%PDF'):
                ext_score = 1.0
        elif ext == '.png':
            if file_data.startswith(b'\x89PNG\r\n\x1a\n'):
                ext_score = 1.0
        elif ext in ('.jpg', '.jpeg'):
            if file_data.startswith(b'\xff\xd8\xff'):
                ext_score = 1.0
        elif ext.endswith(('.txt', '.pdf', '.jpg', '.jpeg', '.png')):
            ext_score = 1.0

        # 4. Printable character ratio
        if file_len > 0:
            printable_ratio = sum(1 for b in file_data if 32 <= b <= 126) / file_len
        else:
            printable_ratio = 0.0

        # 5. Suspicious pattern ratio (high-entropy blocks >= 7.0 / 8.0)
        block_size = 256
        if file_len == 0:
            suspicious_pattern_ratio = 0.0
        elif file_len <= block_size:
            suspicious_pattern_ratio = 1.0 if raw_entropy >= 7.0 else 0.0
        else:
            num_blocks = file_len // block_size
            high_entropy_blocks = 0
            for i in range(num_blocks):
                block = file_data[i * block_size : (i + 1) * block_size]
                if self._calculate_entropy(block) >= 7.0:
                    high_entropy_blocks += 1
            suspicious_pattern_ratio = high_entropy_blocks / num_blocks

        features = [
            float(file_size_mb),
            float(normalized_entropy),
            float(ext_score),
            float(printable_ratio),
            float(suspicious_pattern_ratio)
        ]
        return np.array(features).reshape(1, -1)

    def _train_model(self):
        """
        Train IsolationForest model on 100 synthetic normal samples and save to pickle file.
        Uses contamination=0.1, random_state=42.
        """
        np.random.seed(42)
        normal_samples = []
        for _ in range(100):
            # Normal distribution centered on typical benign document features
            size_mb = max(0.0001, float(np.random.normal(0.05, 0.04)))
            entropy_norm = min(1.0, max(0.0, float(np.random.normal(0.50, 0.08))))
            ext_score = 1.0
            printable = min(1.0, max(0.0, float(np.random.normal(0.95, 0.04))))
            suspicious = max(0.0, float(np.random.uniform(0.0, 0.02)))
            normal_samples.append([size_mb, entropy_norm, ext_score, printable, suspicious])

        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(normal_samples)

        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)

    def _load_or_train(self):
        """
        Load existing model from pickle file or train a new model if it does not exist.
        """
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
            except Exception:
                self._train_model()
        else:
            self._train_model()

    def scan(self, file_data: bytes, filename: str) -> dict:
        """
        Scan file data for threats using the trained IsolationForest model.

        Returns:
            dict with:
                - 'safe': bool (True if normal, False if anomaly/threat)
                - 'anomaly_score': float (IsolationForest decision function score)
                - 'features': list of float feature values
        """
        features = self._extract_features(file_data, filename)
        prediction = self.model.predict(features)[0]
        score = self.model.decision_function(features)[0]

        return {
            'safe': bool(prediction == 1),
            'anomaly_score': float(score),
            'features': features.tolist()[0]
        }


if __name__ == '__main__':
    print("=" * 60)
    print("Testing ThreatDetector (IsolationForest)")
    print("=" * 60)

    detector = ThreatDetector()

    # 1. Test normal benign text file (e.g. realistic user document)
    normal_data = (b"This is a legitimate user document containing normal plain text. " * 300)
    result_normal = detector.scan(normal_data, "report.txt")
    print("\n[+] Benign File Scan (report.txt):")
    print(f"    Safe:          {result_normal['safe']}")
    print(f"    Anomaly Score: {result_normal['anomaly_score']:.4f}")
    print(f"    Features:      {result_normal['features']}")

    # 2. Test high-entropy random byte payload (simulating packed malware/shellcode)
    import secrets
    random_bytes = secrets.token_bytes(2048)
    result_anomaly = detector.scan(random_bytes, "invoice.exe")
    print("\n[+] High-Entropy/Suspicious File Scan (invoice.exe):")
    print(f"    Safe:          {result_anomaly['safe']}")
    print(f"    Anomaly Score: {result_anomaly['anomaly_score']:.4f}")
    print(f"    Features:      {result_anomaly['features']}")

    print("\n[SUCCESS] ThreatDetector initialized, trained, and executed successfully.")
    print("=" * 60)
