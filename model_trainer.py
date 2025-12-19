"""
ML Model Trainer - Trains the anomaly detection model
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os


class ModelTrainer:
    """Train and save anomaly detection model"""
    
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.feature_columns = ['action_encoded', 'status_encoded', 'hour', 'minute']
    
    def prepare_features(self, df):
        """Prepare features for training"""
        df = df.copy()
        
        # Encode categorical variables
        for col in ['action', 'status']:
            if col in df.columns:
                self.label_encoders[col] = LabelEncoder()
                df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col])
        
        # Extract time features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['minute'] = df['timestamp'].dt.minute
        
        return df
    
    def train_model(self, log_file):
        """Train the anomaly detection model"""
        
        print("\n" + "="*80)
        print("🤖 TRAINING ANOMALY DETECTION MODEL")
        print("="*80 + "\n")
        
        # Load training data
        print(f"📂 Loading training data from: {log_file}")
        df = pd.read_csv(log_file)
        print(f"✅ Loaded {len(df)} log entries\n")
        
        # Prepare features
        print("🔧 Preparing features...")
        df_processed = self.prepare_features(df)
        
        # Get feature matrix
        X = df_processed[self.feature_columns]
        print(f"✅ Feature matrix shape: {X.shape}\n")
        
        # Train Isolation Forest model
        print("🧠 Training Isolation Forest model...")
        self.model = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        
        self.model.fit(X)
        print("✅ Model training complete!\n")
        
        # Test predictions
        predictions = self.model.predict(X)
        anomaly_count = sum(predictions == -1)
        print(f"📊 Training set analysis:")
        print(f"   - Total samples: {len(predictions)}")
        print(f"   - Detected anomalies: {anomaly_count}")
        print(f"   - Anomaly rate: {anomaly_count/len(predictions)*100:.2f}%\n")
        
        return True
    
    def save_model(self, output_path='models/anomaly_model.pkl'):
        """Save the trained model"""
        
        if self.model is None:
            print("❌ No model to save. Train first!")
            return False
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save model and encoders
        model_data = {
            'model': self.model,
            'encoders': self.label_encoders,
            'feature_columns': self.feature_columns
        }
        
        joblib.dump(model_data, output_path)
        print(f"💾 Model saved to: {output_path}\n")
        
        return True


def main():
    """Main training function"""
    
    trainer = ModelTrainer()
    
    # Check for training data
    training_file = 'logs/security_logs.csv'
    
    if not os.path.exists(training_file):
        print(f"❌ Training data not found: {training_file}")
        print("   Run log_generator.py first to create training data!")
        return
    
    # Train model
    if trainer.train_model(training_file):
        # Save model
        trainer.save_model()
        
        print("="*80)
        print("✅ MODEL TRAINING COMPLETE!")
        print("="*80)
        print("You can now run ml_detector.py to detect anomalies!")
        print("="*80 + "\n")


if __name__ == "__main__":
    main()
