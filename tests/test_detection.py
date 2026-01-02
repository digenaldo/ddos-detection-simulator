"""
Unit tests for the detection module.
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import numpy as np

from app.feature_extraction import FlowTracker, FlowFeatures, calculate_flow_features
from app.model_prediction import ModelPredictor, predict_attack


class TestFlowTracker(unittest.TestCase):
    """Tests for the flow tracker."""
    
    def setUp(self):
        """Initial setup for each test."""
        self.tracker = FlowTracker(timeout=300.0)
    
    def test_create_flow(self):
        """Test creation of new flow."""
        flow_id = ("192.168.1.1", "192.168.1.2", 12345, 80)
        flow = self.tracker.get_or_create_flow(flow_id, 1000.0, 20, 8192)
        
        self.assertIsInstance(flow, FlowFeatures)
        self.assertEqual(flow.flow_id, flow_id)
        self.assertEqual(flow.start_time, 1000.0)
        self.assertEqual(flow.init_win_bytes_forward, 8192)
    
    def test_get_existing_flow(self):
        """Test getting existing flow."""
        flow_id = ("192.168.1.1", "192.168.1.2", 12345, 80)
        flow1 = self.tracker.get_or_create_flow(flow_id, 1000.0, 20, 8192)
        flow2 = self.tracker.get_or_create_flow(flow_id, 1001.0, 20, 8192)
        
        self.assertIs(flow1, flow2)  # Same instance
        self.assertEqual(flow2.end_time, 1001.0)
    
    def test_cleanup_expired_flows(self):
        """Test cleanup of expired flows."""
        flow_id = ("192.168.1.1", "192.168.1.2", 12345, 80)
        flow = self.tracker.get_or_create_flow(flow_id, 1000.0, 20, 8192)
        flow.end_time = 1000.0
        
        # Cleanup expired flows (timeout of 300s)
        self.tracker.cleanup_expired_flows(1400.0)  # 400s later
        
        self.assertIsNone(self.tracker.get_flow(flow_id))


class TestFeatureExtraction(unittest.TestCase):
    """Tests for feature extraction."""
    
    def test_calculate_flow_features_invalid_packet(self):
        """Test extraction with invalid packet."""
        invalid_packet = Mock()
        del invalid_packet.ip  # Remove IP attribute
        
        result = calculate_flow_features(invalid_packet)
        self.assertIsNone(result)
    
    @patch('app.feature_extraction._flow_tracker')
    def test_calculate_flow_features_valid_packet(self, mock_tracker):
        """Test extraction with valid packet."""
        # Create packet mock
        packet = Mock()
        packet.ip.src = "192.168.1.1"
        packet.ip.dst = "192.168.1.2"
        packet.tcp.srcport = "12345"
        packet.tcp.dstport = "80"
        packet.tcp.hdr_len = "20"
        packet.tcp.window_size = "8192"
        packet.tcp.flags = "0x018"
        packet.length = 100
        packet.sniff_time.timestamp.return_value = 1000.0
        
        # Tracker mock
        flow = FlowFeatures(
            flow_id=("192.168.1.1", "192.168.1.2", 12345, 80),
            start_time=1000.0,
            end_time=1000.0
        )
        mock_tracker.get_or_create_flow.return_value = flow
        
        result = calculate_flow_features(packet)
        
        # Verify that it returned a list of features
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)


class TestModelPrediction(unittest.TestCase):
    """Tests for model prediction."""
    
    @patch('app.model_prediction.joblib.load')
    @patch('app.model_prediction.Config')
    def test_model_predictor_initialization(self, mock_config, mock_load):
        """Test predictor initialization."""
        # Model and scaler mock
        mock_model = Mock()
        mock_model.predict.return_value = np.array([0])
        mock_model.predict_proba.return_value = np.array([[0.9, 0.1]])
        
        mock_scaler = Mock()
        mock_scaler.n_features_in_ = 78
        mock_scaler.transform.return_value = np.array([[1.0] * 78])
        
        mock_load.side_effect = [mock_model, mock_scaler]
        
        # Paths mock
        mock_config.MODEL_PATH.exists.return_value = True
        mock_config.SCALER_PATH.exists.return_value = True
        
        predictor = ModelPredictor()
        
        self.assertIsNotNone(predictor.model)
        self.assertIsNotNone(predictor.scaler)
    
    @patch('app.model_prediction.get_predictor')
    def test_predict_attack(self, mock_get_predictor):
        """Test attack prediction function."""
        # Predictor mock
        mock_predictor = Mock()
        mock_predictor.predict.return_value = (1, 0.95)  # Attack detected
        mock_get_predictor.return_value = mock_predictor
        
        features = [0.0] * 78  # Example features
        predict_attack(features)
        
        mock_predictor.predict.assert_called_once_with(features)
    
    def test_predict_attack_none_features(self):
        """Test prediction with None features."""
        with patch('app.model_prediction.logger') as mock_logger:
            predict_attack(None)
            mock_logger.warning.assert_called()


class TestIntegration(unittest.TestCase):
    """Basic integration tests."""
    
    def test_flow_features_dataclass(self):
        """Test that FlowFeatures is a valid dataclass."""
        flow = FlowFeatures(
            flow_id=("192.168.1.1", "192.168.1.2", 12345, 80),
            start_time=1000.0,
            end_time=1001.0
        )
        
        self.assertEqual(flow.start_time, 1000.0)
        self.assertEqual(flow.end_time, 1001.0)
        self.assertEqual(len(flow.fwd_packet_lengths), 0)


if __name__ == '__main__':
    unittest.main()
