"""
AI/ML Anomaly Detection — CYC386 MVP
Algorithm: Isolation Forest (unsupervised, good for log-based anomaly detection)
Input: HTTP request metrics from Prometheus
Maps to: NIST CSF DE.AE-1, DE.AE-2
"""

import json
import time
import numpy as np
import requests
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime

logger = structlog.get_logger()

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
MODEL_PATH = "models/isolation_forest.joblib"
SCALER_PATH = "models/scaler.joblib"
ALERT_THRESHOLD = -0.3   # Anomaly score below this → alert


class AnomalyDetector:
    """
    Fetches metrics from Prometheus and detects anomalies using Isolation Forest.
    Features used:
      - Request rate (req/s)
      - Error rate (4xx + 5xx / total)
      - P99 response latency
      - Unique IP count (approximate)
    """

    def __init__(self, contamination=0.05):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,   # Expected ~5% anomalies
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def fetch_metrics(self) -> dict:
        """Query Prometheus for current metrics"""
        queries = {
            "request_rate": 'rate(http_requests_total[5m])',
            "error_rate": 'rate(http_requests_total{status=~"4..|5.."}[5m])',
            "p99_latency": 'histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))',
        }

        metrics = {}
        for name, query in queries.items():
            try:
                resp = requests.get(
                    f"{PROMETHEUS_URL}/api/v1/query",
                    params={"query": query},
                    timeout=5,
                )
                data = resp.json()
                if data["data"]["result"]:
                    value = float(data["data"]["result"][0]["value"][1])
                    metrics[name] = value
                else:
                    metrics[name] = 0.0
            except Exception as e:
                logger.warning("prometheus_query_failed", query=name, error=str(e))
                metrics[name] = 0.0

        return metrics

    def metrics_to_features(self, metrics: dict) -> np.ndarray:
        """Convert metrics dict to feature vector"""
        return np.array([[
            metrics.get("request_rate", 0),
            metrics.get("error_rate", 0),
            metrics.get("p99_latency", 0),
        ]])

    def train(self, historical_data: list[dict]):
        """Train the model on historical (normal) metrics"""
        X = np.array([
            [d["request_rate"], d["error_rate"], d["p99_latency"]]
            for d in historical_data
        ])
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

        # Persist model
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        logger.info("model_trained", samples=len(historical_data))

    def load_model(self):
        """Load persisted model"""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.is_trained = True
            logger.info("model_loaded")
        else:
            logger.warning("no_model_found_will_train_online")

    def detect(self, metrics: dict) -> dict:
        """
        Run anomaly detection on current metrics.
        Returns anomaly score and whether an alert should be raised.
        """
        if not self.is_trained:
            return {"anomaly": False, "score": 0.0, "reason": "model_not_trained"}

        features = self.metrics_to_features(metrics)
        features_scaled = self.scaler.transform(features)

        # Isolation Forest: +1 = normal, -1 = anomaly
        prediction = self.model.predict(features_scaled)[0]
        score = self.model.score_samples(features_scaled)[0]

        is_anomaly = prediction == -1 or score < ALERT_THRESHOLD

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "anomaly": is_anomaly,
            "score": float(score),
            "prediction": int(prediction),
            "metrics": metrics,
            "alert_level": "HIGH" if score < -0.5 else ("MEDIUM" if is_anomaly else "NONE"),
        }

        if is_anomaly:
            logger.warning(
                "anomaly_detected",
                score=score,
                metrics=metrics,
                alert_level=result["alert_level"],
            )
            # In prod: send to QRadar SIEM via syslog or REST API
            self._send_to_siem(result)

        return result

    def _send_to_siem(self, alert: dict):
        """
        Send alert to SIEM (IBM QRadar via syslog).
        In prod: configure QRadar log source for Python app.
        """
        import syslog
        try:
            syslog.openlog("secureapp-anomaly", syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(
                syslog.LOG_WARNING,
                f"ANOMALY_DETECTED score={alert['score']:.3f} "
                f"level={alert['alert_level']} metrics={json.dumps(alert['metrics'])}"
            )
        except Exception as e:
            logger.error("siem_alert_failed", error=str(e))

    def run_continuous(self, interval_seconds=60):
        """Continuous monitoring loop"""
        self.load_model()
        logger.info("anomaly_detector_started", interval=interval_seconds)

        while True:
            try:
                metrics = self.fetch_metrics()
                result = self.detect(metrics)
                logger.info(
                    "detection_cycle",
                    anomaly=result["anomaly"],
                    score=result.get("score"),
                    alert_level=result.get("alert_level"),
                )
            except Exception as e:
                logger.error("detection_error", error=str(e))

            time.sleep(interval_seconds)


if __name__ == "__main__":
    detector = AnomalyDetector()

    # Quick demo: generate synthetic training data
    print("Generating synthetic training data...")
    normal_data = [
        {
            "request_rate": np.random.normal(50, 10),
            "error_rate": np.random.normal(0.02, 0.005),
            "p99_latency": np.random.normal(0.2, 0.05),
        }
        for _ in range(500)
    ]
    detector.train(normal_data)

    # Simulate anomaly detection
    test_cases = [
        {"request_rate": 55, "error_rate": 0.02, "p99_latency": 0.22, "label": "NORMAL"},
        {"request_rate": 500, "error_rate": 0.8, "p99_latency": 5.0, "label": "ATTACK"},
        {"request_rate": 5, "error_rate": 0.5, "p99_latency": 10.0, "label": "OUTAGE"},
    ]

    print("\n── Anomaly Detection Results ──")
    for case in test_cases:
        label = case.pop("label")
        result = detector.detect(case)
        print(
            f"[{label:8s}] anomaly={result['anomaly']} "
            f"score={result['score']:.3f} "
            f"alert={result['alert_level']}"
        )
