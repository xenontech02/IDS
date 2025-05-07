import pandas as pd
from sklearn.ensemble import IsolationForest
import smtplib
from email.mime.text import MIMEText

class IntrusionDetectionSystem:
    def __init__(self, alert_threshold=0.5, email_notifications=False, email_config=None):
        self.alert_threshold = alert_threshold
        self.email_notifications = email_notifications
        self.email_config = email_config
        self.model = IsolationForest(contamination=alert_threshold)
        self.traffic_data = pd.DataFrame(columns=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'length'])

    def load_data(self, file_path):
        self.traffic_data = pd.read_csv(file_path)
        self.train_model()

    def train_model(self):
        feature_columns = ['src_port', 'dst_port', 'length']
        self.model.fit(self.traffic_data[feature_columns].dropna())

    def detect_anomalies(self):
        feature_columns = ['src_port', 'dst_port', 'length']
        if not self.traffic_data[feature_columns].isnull().values.any():
            predictions = self.model.predict(self.traffic_data[feature_columns])
            for index, prediction in enumerate(predictions):
                if prediction == -1:  # Anomaly detected
                    self.alert(self.traffic_data.iloc[index])

    def alert(self, packet_data):
        alert_message = f"Suspicious activity detected: {packet_data.to_dict()}"
        print(alert_message)
        if self.email_notifications and self.email_config:
            self.send_email_alert(alert_message)

    def send_email_alert(self, message):
        msg = MIMEText(message)
        msg['Subject'] = 'Intrusion Detection Alert'
        msg['From'] = self.email_config['from_email']
        msg['To'] = self.email_config['to_email']

        with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
            server.starttls()
            server.login(self.email_config['from_email'], self.email_config['password'])
            server.sendmail(self.email_config['from_email'], [self.email_config['to_email']], msg.as_string())

if __name__ == "__main__":
    email_config = {
        'from_email': 'xestories@gmail.com',
        'to_email': 'xenonshare@gmail.com',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'password': 'knkq aijr fjod poos'
    }
    ids = IntrusionDetectionSystem(alert_threshold=0.1, email_notifications=True, email_config=email_config)
    ids.load_data('network_traffic.csv')
    ids.detect_anomalies()