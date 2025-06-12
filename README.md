# Email Phishing Detection System

A machine learning-based system to detect phishing emails.

## Features

- Advanced email analysis
- Machine learning-based classification
- Real-time email analysis
- Comprehensive feature extraction

## Quick Start

1. Clone the repository:
```bash
git clone <your-repo-url>
cd EMAIL-PHISHING
```

2. Create and activate virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Analyze emails:
```bash
python email_analyzer.py
```

## Project Structure

- `train_model.py`: Training script for the phishing detection model (optional)
- `email_analyzer.py`: Main email analysis application
- `analyze_my_email.py`: Example script for analyzing emails
- `phishing_model.pkl`: Pre-trained model for email analysis
- `feature_names.pkl`: Feature names used in the model

## Usage

1. Email Analysis (Recommended):
   - The project comes with a pre-trained model
   - Simply run `python email_analyzer.py`
   - The script will analyze emails and provide detailed reports

2. Model Training (Optional):
   - If you want to train your own model:
     - Download the required datasets
     - Run `python train_model.py`
     - The new model will be saved as `phishing_model.pkl`

## Notes

- The project comes with a pre-trained model, so training is optional
- You can start analyzing emails immediately after setup
- Training is only needed if you want to customize the model
- The pre-trained model has been tested and optimized

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License

## Notes

- The CSV files are not included in the repository due to their size
- You must download the datasets separately to train the model
- The model will only work after proper training with the datasets
- Ensure you have sufficient disk space for the datasets and model files
