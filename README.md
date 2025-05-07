# Intrusion Detection System (IDS) Simulation

This project is a simple Intrusion Detection System (IDS) simulation using Python and machine learning. It demonstrates how to detect anomalous network traffic using the Isolation Forest algorithm and can send email alerts when suspicious activity is detected.

## Features
- Loads and analyzes network traffic data from a CSV file
- Detects anomalies in network traffic using Isolation Forest
- Configurable alert threshold for anomaly detection
- Optional email notifications for detected intrusions

## Project Structure
- `ids_simulation.py`: Main Python script containing the IDS logic
- `network_traffic.csv`: Example CSV file with simulated network traffic data

## Requirements
- Python 3.7+
- pandas
- scikit-learn

## Installation
1. Clone this repository or download the files.
2. Install the required dependencies:
   ```bash
   pip install pandas scikit-learn
   ```

## Usage
1. Edit the email configuration in `ids_simulation.py` if you want to enable email alerts.
2. Place your network traffic data in `network_traffic.csv` (ensure it has columns: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `length`).
3. Run the simulation:
   ```bash
   python ids_simulation.py
   ```

## Email Alerts
To enable email notifications, set `email_notifications=True` and provide the correct `email_config` dictionary with your SMTP server details and credentials. **Do not share your email password publicly.**

## Example
```
Suspicious activity detected: {'src_ip': '...', 'dst_ip': '...', 'src_port': ..., 'dst_port': ..., 'protocol': '...', 'length': ...}
```

## License
This project is for educational purposes.
