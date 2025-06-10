# Email Phishing Detection System

A machine learning-based system to detect phishing emails.

## Features

- Advanced email analysis
- Machine learning-based classification
- Real-time email analysis
- Comprehensive feature extraction

## Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd EMAIL-PHISHING
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Project Structure

- `train_model.py`: Training script for the phishing detection model
- `email_analyzer.py`: Main email analysis application
- `analyze_my_email.py`: Example script for analyzing emails
- `emails.csv`: Main dataset
- `spam-emails.csv`: Spam dataset
- `phishing_model.pkl`: Trained model (generated after training)
- `feature_names.pkl`: Feature names used in the model

## Usage

1. Train the model:
```bash
python train_model.py
```

2. Analyze emails:
```bash
python email_analyzer.py
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License
