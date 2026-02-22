"""
ML-Powered SQL Injection Scanner
EXACT copy of sqli_js.py with ONE change:
- Detection logic replaced with ML model (gradient_boosting_model.pkl)
- ML model analyzes RESPONSE to determine if SQLi succeeded
- Everything else identical: crawling, payloads, counting, output format
"""

# This file will import and extend sqli_js, replacing ONLY the detection logic
# To keep it maintainable, we'll create a new detector class that uses ML

import sys
import joblib
import pandas as pd
import re
import warnings
from typing import List, Tuple

# Suppress sklearn version warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
# Suppress XGBoost pickle warning
warnings.filterwarnings("ignore", message=".*XGBoost.*")

from sqli_js import (
    EnhancedSQLiScanner,
    DetectionResult,
    VulnerabilityLevel,
    get_all_payloads,
    COMMON_PATHS
)

class MLSQLiDetector:
    """
    ML-based detector that replaces SQLiDetector.
    Uses trained model to analyze responses instead of pattern matching.
    """
    
    def __init__(
        self,
        baseline_response=None,
        baseline_length=None,
        time_threshold=3.0,
        length_threshold=0.25,
        growth_threshold=50,
    ):
        self.baseline_response = baseline_response
        self.baseline_length = baseline_length or (len(baseline_response) if baseline_response else 0)
        self.time_threshold = time_threshold
        
        # Load ML model (Cached global to avoid reloading per request)
        global _ML_MODEL_CACHE
        if '_ML_MODEL_CACHE' not in globals():
            _ML_MODEL_CACHE = {'model': None, 'scaler': None, 'features': None}
            
        if _ML_MODEL_CACHE['model'] is None:
            try:
                _ML_MODEL_CACHE['model'] = joblib.load('xgboost_model.pkl')
                _ML_MODEL_CACHE['scaler'] = joblib.load('feature_scaler.pkl')
                _ML_MODEL_CACHE['features'] = joblib.load('feature_names.pkl')
                print("[*] ML model loaded successfully")
            except Exception as e:
                print(f"[!] Error loading ML model: {e}")
                print("[!] Run 'python save_best_model.py' first!")
                sys.exit(1)
        
        self.model = _ML_MODEL_CACHE['model']
        self.scaler = _ML_MODEL_CACHE['scaler']
        self.feature_names = _ML_MODEL_CACHE['features']
    
    def extract_payload_features(self, payload):
        """Extract payload features (22 features)"""
        if not payload:
            return {
                'has_single_quote': 0, 'has_double_quote': 0, 'has_semicolon': 0,
                'has_comment': 0, 'has_union': 0, 'has_select': 0, 'has_or_logic': 0,
                'has_and_logic': 0, 'has_sleep': 0, 'has_waitfor': 0, 'has_benchmark': 0,
                'has_substring': 0, 'has_concat': 0, 'has_tautology': 0, 'has_null_byte': 0,
                'has_url_encoding': 0, 'has_hex_encoding': 0, 'has_whitespace_obfuscation': 0,
                'payload_length': 0, 'special_char_count': 0, 'digit_count': 0, 'special_char_ratio': 0,
            }
        
        payload_str = str(payload).lower()
        
        return {
            'has_single_quote': int("'" in payload_str),
            'has_double_quote': int('"' in payload_str),
            'has_semicolon': int(';' in payload_str),
            'has_comment': int('--' in payload_str or '#' in payload_str or '/*' in payload_str),
            'has_union': int(re.search(r'\bunion\b', payload_str) is not None),
            'has_select': int(re.search(r'\bselect\b', payload_str) is not None),
            'has_or_logic': int(re.search(r'\bor\b', payload_str) is not None),
            'has_and_logic': int(re.search(r'\band\b', payload_str) is not None),
            'has_sleep': int(re.search(r'\bsleep\b', payload_str) is not None),
            'has_waitfor': int(re.search(r'\bwaitfor\b', payload_str) is not None),
            'has_benchmark': int(re.search(r'\bbenchmark\b', payload_str) is not None),
            'has_substring': int(re.search(r'\bsubstring\b', payload_str) is not None),
            'has_concat': int(re.search(r'\bconcat\b', payload_str) is not None),
            'has_tautology': int(re.search(r"('1'='1'|1=1)", payload_str) is not None),
            'has_null_byte': int('%00' in payload_str),
            'has_url_encoding': int('%' in str(payload) and re.search(r'%[0-9a-fA-F]{2}', str(payload)) is not None),
            'has_hex_encoding': int(re.search(r'0x[0-9a-fA-F]+', payload_str) is not None),
            'has_whitespace_obfuscation': int(any(x in payload_str for x in ['%09', '%0a', '%0d', '%20'])),
            'payload_length': min(len(payload), 500),
            'special_char_count': min(len(re.findall(r'[^a-zA-Z0-9\s]', payload_str)), 50),
            'digit_count': len(re.findall(r'\d', payload_str)),
            'special_char_ratio': len(re.findall(r'[^a-zA-Z0-9\s]', payload_str)) / max(len(payload_str), 1),
        }
    
    def extract_response_features(self, response_text, response_length, response_time):
        """Extract response features (21 features)"""
        features = {
            'response_time': float(response_time),
            'is_slow_response': int(response_time > 3.0),
            'is_very_slow_response': int(response_time > 5.0),
            'response_length': int(response_length),
            'is_large_response': int(response_length > 2000),
            'is_small_response': int(response_length < 500),
        }
        
        if response_text:
            resp_str = response_text.lower()
            
            # PRECISE SQL error detection
            features['has_sql_error_keywords'] = int(any(pattern in resp_str for pattern in [
                'sql syntax', 'syntax error', 'mysql error', 'mysqli error', 
                'you have an error in your sql', 'check the manual that corresponds',
                'sqlstate', 'sql server error', 'ora-', 'pg_query()', 'pg_exec()',
                'mysql_fetch', 'mysqli_fetch', 'error in your sql syntax'
            ]))
            features['has_database_keywords'] = int(any(kw in resp_str for kw in 
                ['database', 'table', 'select', 'from', 'where']))
            features['has_php_error'] = int('php' in resp_str and any(kw in resp_str for kw in 
                ['warning', 'error', 'notice']))
            features['has_warning_keyword'] = int(any(kw in resp_str for kw in 
                ['warning', 'exception']))
            features['has_version_info'] = int(bool(re.search(r'\d+\.\d+\.\d+', resp_str)))
            features['has_table_structure'] = int('table' in resp_str and 'column' in resp_str)
            features['has_union_output'] = int(resp_str.count('your login name') > 0 or 
                                                resp_str.count('your password') > 0)
            
            # Credential leakage
            features['has_login_keyword'] = int(any(kw in resp_str for kw in 
                ['login name', 'login:', 'username:', 'user:']))
            features['has_password_keyword'] = int(any(kw in resp_str for kw in 
                ['password', 'pass:', 'passwd']))
            features['has_admin_keyword'] = int(any(kw in resp_str for kw in 
                ['admin', 'administrator', 'root']))
            features['has_user_data'] = int(any(kw in resp_str for kw in 
                ['dumb', 'dhakkan', 'angelina', 'dummy']))
            features['has_colon_value_pairs'] = int(resp_str.count(':') > 5)
            features['response_contains_credentials'] = int(
                (features['has_login_keyword'] and features['has_password_keyword']) or
                features['has_user_data']
            )
            
            features['response_has_html'] = int('<html' in resp_str or '<body' in resp_str)
            features['response_line_count'] = min(resp_str.count('\n'), 100)
        else:
            features.update({
                'has_sql_error_keywords': 0, 'has_database_keywords': 0, 'has_php_error': 0,
                'has_warning_keyword': 0, 'has_version_info': 0, 'has_table_structure': 0,
                'has_union_output': 0, 'has_login_keyword': 0, 'has_password_keyword': 0,
                'has_admin_keyword': 0, 'has_user_data': 0, 'has_colon_value_pairs': 0,
                'response_contains_credentials': 0, 'response_has_html': 0, 'response_line_count': 0,
            })
        
        return features
    
    def detect_sql_errors(self, response_text):
        """For compatibility - returns empty as ML handles detection"""
        return [], []
    
    def analyze(self, response_text, response_time, payload="", baseline_text=""):
        """
        ML-based analysis replacing pattern matching.
        Returns DetectionResult based on ML model prediction.
        """
        # Extract all 44 features
        payload_features = self.extract_payload_features(payload)
        response_features = self.extract_response_features(response_text, len(response_text), response_time)
        
        # Combine features
        all_features = {**payload_features, **response_features, 'method_encoded': 0}
        
        # Create DataFrame
        feature_df = pd.DataFrame([all_features])
        feature_df = feature_df[self.feature_names]
        
        # Scale and predict
        features_scaled = self.scaler.transform(feature_df)
        prediction_prob = self.model.predict_proba(features_scaled)[0][1]
        prediction = self.model.predict(features_scaled)[0]
        
        # Build detailed evidence list with feature analysis
        evidence = []
        if prediction == 1:
            evidence.append(f"ML Confidence: {prediction_prob:.4f} ({prediction_prob*100:.2f}%)")
            
            # Add specific indicators if present
            if response_features.get('has_sql_error_keywords'):
                evidence.append("✓ SQL error keywords detected")
            if response_features.get('response_contains_credentials'):
                evidence.append("✓ Credential leakage detected")
            if response_features.get('is_very_slow_response'):
                evidence.append(f"✓ Time delay: {response_time:.2f}s")
            if response_features.get('has_database_keywords'):
                evidence.append("✓ Database keywords in response")
            if response_features.get('has_php_error'):
                evidence.append("✓ PHP error detected")
            
            # Add payload analysis
            if payload_features.get('has_union'):
                evidence.append("Payload: UNION-based")
            if payload_features.get('has_or_logic'):
                evidence.append("Payload: OR-based tautology")
            if payload_features.get('has_sleep'):
                evidence.append("Payload: Time-based (SLEEP)")
            
            # Show why it passed/failed threshold
            has_strong_indicators = (
                response_features.get('has_sql_error_keywords') or 
                response_features.get('response_contains_credentials')
            )
            if has_strong_indicators:
                evidence.append(f"Threshold: Relaxed (has explicit indicators)")
            else:
                evidence.append(f"Threshold: Strict (pure ML detection)")
        
        # PRAGMATIC Threshold System
        # Model has low confidence scores (avg 40%), so we need lower thresholds
        # to catch ANY vulnerabilities while still filtering obvious false positives
        
        # Count strong indicators
        has_sql_errors = response_features.get('has_sql_error_keywords', 0)
        has_credentials = response_features.get('response_contains_credentials', 0)
        has_time_delay = response_features.get('is_very_slow_response', 0)
        has_db_keywords = response_features.get('has_database_keywords', 0)
        
        strong_indicator_count = sum([has_sql_errors, has_credentials, has_time_delay])
        
        # PRAGMATIC RULES (lowered by 10% from balanced):
        # Accept that model has low confidence, focus on indicators
        
        if prediction == 0:
            level = VulnerabilityLevel.NOT_VULNERABLE
        elif prediction == 1:
            # Time-based SQLi: Often no SQL errors
            if has_time_delay and prediction_prob >= 0.85:  # Was 0.95
                level = VulnerabilityLevel.LIKELY_VULNERABLE
            
            # SQL errors or credentials present: Real vulnerabilities
            elif (has_sql_errors or has_credentials):
                if prediction_prob >= 0.85:  # Was 0.95
                    level = VulnerabilityLevel.LIKELY_VULNERABLE
                elif prediction_prob >= 0.70:  # Was 0.85
                    level = VulnerabilityLevel.POSSIBLY_VULNERABLE
                else:
                    level = VulnerabilityLevel.NOT_VULNERABLE
            
            # Pure ML detection (no obvious indicators)
            else:
                if prediction_prob >= 0.90:  # Was 0.99
                    level = VulnerabilityLevel.LIKELY_VULNERABLE
                elif prediction_prob >= 0.80:  # Was 0.97
                    level = VulnerabilityLevel.POSSIBLY_VULNERABLE
                else:
                    level = VulnerabilityLevel.NOT_VULNERABLE
        else:
            level = VulnerabilityLevel.NOT_VULNERABLE
        
        # Store additional diagnostic info in the result
        result = DetectionResult(
            level=level,
            evidence=evidence,
            response_length=len(response_text),
            response_time=response_time,
            error_messages=[],  # ML doesn't extract specific error messages
            confidence_score=prediction_prob if prediction == 1 else (1 - prediction_prob)
        )
        
        # Add custom attributes for detailed reporting
        result.ml_confidence = prediction_prob
        result.ml_prediction = prediction
        result.payload_used = payload
        result.response_features = response_features
        result.payload_features = payload_features
        
        return result


# Monkey-patch the detector in sqli_js
import sqli_js
original_detector_class = sqli_js.SQLiDetector
sqli_js.SQLiDetector = MLSQLiDetector

if __name__ == "__main__":
    print("="*60)
    print("ML-POWERED SQL INJECTION SCANNER")
    print("(Exact sqli_js logic with ML detection)")
    print("="*60)
    print()
    
    # Use sqli_js's main function but with ML detector
    from sqli_js import main
    main()