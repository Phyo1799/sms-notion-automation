from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
import requests
import re
from datetime import datetime
import os
from dotenv import load_dotenv
import csv
import io
import socket
import qrcode
from PIL import Image
import ssl
import secrets
from functools import lru_cache
import time
import logging

load_dotenv()

NOTION_API_KEY = os.getenv('NOTION_API_KEY')
DATABASE_ID = os.getenv('DATABASE_ID')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SSL_CERTIFICATE'] = os.getenv('SSL_CERTIFICATE', 'cert.pem')
app.config['SSL_KEY'] = os.getenv('SSL_KEY', 'key.pem')

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for authentication
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Simple user database (replace with proper database in production)
USERS = {
    os.getenv('ADMIN_EMAIL', 'admin@example.com'): {
        'password': os.getenv('ADMIN_PASSWORD', 'admin123'),
        'name': 'Admin'
    }
}

# Account mapping for display names
ACCOUNT_MAPPING = {
    "433e6ffadc44482e811c989bff9b9812": "HSBC",
    "1c374f2347e580ac90aed5e1e7a86e32": "E&money"
}

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in USERS else None

# Login form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        if email in USERS and USERS[email]['password'] == form.password.data:
            user = User(email)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('index.html')

# Cache QR code for 5 minutes
@lru_cache(maxsize=1)
def generate_qr_code(url, timestamp):
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5,
        error_correction=qrcode.constants.ERROR_CORRECT_L
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save QR code to bytes
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    
    return img_byte_arr.getvalue()

@app.route('/qr')
@login_required
def generate_qr():
    # Generate QR code for the current URL
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    url = f"http://{local_ip}:8080"
    
    # Use timestamp to force cache refresh every 5 minutes
    timestamp = int(time.time() / 300)
    
    # Generate and cache QR code
    qr_data = generate_qr_code(url, timestamp)
    
    return send_file(
        io.BytesIO(qr_data),
        mimetype='image/png',
        cache_timeout=300  # Cache for 5 minutes
    )

# Add these routes before the if __name__ == '__main__' block
@app.route('/messages', methods=['GET'])
@login_required
def get_messages():
    try:
        # In a real application, you would fetch messages from a database
        # For now, we'll return an empty list
        return jsonify({
            'success': True,
            'messages': []
        })
    except Exception as e:
        logger.error(f"Error getting messages: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/send_sms', methods=['POST'])
@login_required
def send_sms():
    try:
        data = request.get_json()
        sms_text = data.get('sms_text', '')
        
        if not sms_text:
            return jsonify({
                'success': False,
                'error': 'No message provided'
            }), 400
            
        parsed_data = parse_sms(sms_text)
        
        if all(parsed_data.values()):
            result = add_to_notion(parsed_data)
            return jsonify({
                'success': True,
                'data': {
                    'merchant': parsed_data['merchant'],
                    'amount': parsed_data['amount'],
                    'date': parsed_data['date'],
                    'accounts': [get_account_name(acc_id) for acc_id in parsed_data['account_ids']]
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Could not parse all required information',
                'parsed_data': parsed_data
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_sms(text):
    logger.debug(f"Starting SMS parsing for text: {text}")
    
    # Initialize variables
    amount = None
    merchant = None
    date = None
    account_ids = []

    try:
        # Check if it's an HSBC message
        if "from hsbc:" in text.lower():
            logger.debug("Detected HSBC message")
            # Extract amount from HSBC format
            amount_match = re.search(r'AED\s+([\d,]+\.\d+)[+-]', text)
            if amount_match:
                amount = float(amount_match.group(1).replace(',', ''))
                # Remove the logic that checks for a negative sign
                logger.debug(f"Extracted amount: {amount}")
            
            # Extract date from HSBC format
            date_match = re.search(r'(\d{2}[A-Za-z]{3}\d{2})', text)
            if date_match:
                date_str = date_match.group(1)
                try:
                    date_str = date_str[:2] + date_str[2:5].upper() + date_str[5:]
                    date_obj = datetime.strptime(date_str, '%d%b%y')
                    date = date_obj.strftime('%Y-%m-%d')
                    logger.debug(f"Extracted date: {date}")
                except ValueError as e:
                    logger.error(f"Date parsing error: {e} for date string: {date_str}")
                    date = None
            
            # Extract merchant name between date and "Purchase"
            merchant_match = re.search(r'\d{2}[A-Za-z]{3}\d{2}\s+(.*?)\s+Purchase', text)
            if merchant_match:
                merchant = merchant_match.group(1).strip()
                logger.debug(f"Extracted merchant: {merchant}")

            account_ids.append("433e6ffadc44482e811c989bff9b9812")
            logger.debug("Added HSBC account ID")

        # Check if it's an e&money message
        elif "e& money card" in text.lower() or "e&money card" in text.lower():
            logger.debug("Detected e&money message")
            
            # Extract amount
            amount_match = re.search(r'AED\s+(\d+\.\d+)', text)
            if amount_match:
                amount = float(amount_match.group(1))
                logger.debug(f"Extracted amount: {amount}")

            # Extract merchant name
            merchant_match = re.search(r'at\s+(.*?)\s+(?:using|on|with)', text, re.IGNORECASE)
            if merchant_match:
                merchant = merchant_match.group(1).strip()
                logger.debug(f"Extracted merchant: {merchant}")

            # Extract date - try multiple formats
            date_formats = [
                (r'Date:\s*(\d{4}-\d{2}-\d{2})', '%Y-%m-%d'),
                (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
                (r'(\d{2}/\d{2}/\d{4})', '%d/%m/%Y'),
                (r'(\d{2}-\d{2}-\d{4})', '%d-%m-%Y')
            ]

            for pattern, date_format in date_formats:
                date_match = re.search(pattern, text)
                if date_match:
                    try:
                        date_obj = datetime.strptime(date_match.group(1), date_format)
                        date = date_obj.strftime('%Y-%m-%d')
                        logger.debug(f"Extracted date using format {date_format}: {date}")
                        break
                    except ValueError as e:
                        logger.error(f"Date parsing error: {e} for date string: {date_match.group(1)}")
                        continue

            account_ids.append("1c374f2347e580ac90aed5e1e7a86e32")
            logger.debug("Added E&money account ID")

        # Debug information
        logger.debug(f"Final parsed data: amount={amount}, merchant={merchant}, date={date}, account_ids={account_ids}")

        return {
            'amount': amount,
            'merchant': merchant,
            'date': date,
            'account_ids': account_ids
        }

    except Exception as e:
        logger.error(f"Error in parse_sms: {str(e)}", exc_info=True)
        return {
            'amount': None,
            'merchant': None,
            'date': None,
            'account_ids': []
        }

def add_to_notion(data):
    logger.debug(f"Adding to Notion: {data}")
    
    try:
        headers = {
            'Authorization': f'Bearer {NOTION_API_KEY}',
            'Content-Type': 'application/json',
            'Notion-Version': '2022-06-28'
        }

        # Create relation array based on detected accounts
        relations = [{"id": account_id} for account_id in data['account_ids']]
        logger.debug(f"Created relations: {relations}")

        payload = {
            "parent": {
                "database_id": DATABASE_ID
            },
            "properties": {
                "Expense Name": {
                    "title": [
                        {
                            "text": {
                                "content": data['merchant']
                            }
                        }
                    ]
                },
                "Amount": {
                    "number": data['amount']
                },
                "Date": {
                    "date": {
                        "start": data['date']
                    }
                },
                "Accounts": {
                    "relation": relations
                }
            }
        }

        logger.debug(f"Sending request to Notion API with payload: {payload}")

        response = requests.post(
            'https://api.notion.com/v1/pages',
            headers=headers,
            json=payload
        )
        
        if response.status_code != 200:
            logger.error(f"Notion API error: {response.status_code} - {response.text}")
            raise Exception(f"Notion API error: {response.status_code} - {response.text}")
            
        logger.debug(f"Notion API response: {response.json()}")
        return response.json()

    except Exception as e:
        logger.error(f"Error in add_to_notion: {str(e)}", exc_info=True)
        raise

@app.route('/process', methods=['POST'])
@login_required
def process_sms():
    try:
        sms_text = request.json.get('sms_text', '')
        if not sms_text:
            logger.warning("No message provided in request")
            return jsonify({
                'success': False,
                'error': 'No message provided'
            }), 400
            
        logger.debug(f"Processing message: {sms_text}")
        
        parsed_data = parse_sms(sms_text)
        logger.debug(f"Parsed data: {parsed_data}")
        
        if all(parsed_data.values()):
            try:
                result = add_to_notion(parsed_data)
                logger.debug(f"Notion API response: {result}")
                return jsonify({
                    'success': True,
                    'data': {
                        'merchant': parsed_data['merchant'],
                        'amount': parsed_data['amount'],
                        'date': parsed_data['date'],
                        'accounts': [get_account_name(acc_id) for acc_id in parsed_data['account_ids']],
                        'page_id': result.get('id')
                    }
                })
            except Exception as e:
                logger.error(f"Error adding to Notion: {str(e)}", exc_info=True)
                return jsonify({
                    'success': False,
                    'error': f'Failed to add to Notion: {str(e)}'
                }), 500
        else:
            missing_fields = [k for k, v in parsed_data.items() if v is None]
            logger.warning(f"Parsing failed. Missing values: {missing_fields}")
            return jsonify({
                'success': False,
                'error': 'Could not parse all required information',
                'missing_fields': missing_fields,
                'parsed_data': parsed_data
            }), 400
            
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/export', methods=['POST'])
@login_required
def export_csv():
    data = request.json.get('data', [])
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Date', 'Merchant', 'Amount', 'Account'])
    
    # Write data
    for row in data:
        writer.writerow([
            row.get('date', ''),
            row.get('merchant', ''),
            row.get('amount', ''),
            row.get('account', '')
        ])
    
    # Prepare the response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'expenses_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/test_parse', methods=['POST'])
@login_required
def test_parse():
    try:
        sms_text = request.json.get('sms_text', '')
        if not sms_text:
            return jsonify({
                'success': False,
                'error': 'No message provided'
            }), 400
            
        logger.debug("=== Starting Test Parse ===")
        logger.debug(f"Input message: {sms_text}")
        
        # Test regex patterns
        amount_pattern = r'AED\s+(\d+\.\d+)'
        merchant_pattern = r'at\s+(.*?)\s+(?:using|on|with)'
        date_pattern = r'Date:\s*(\d{4}-\d{2}-\d{2})'
        
        amount_match = re.search(amount_pattern, sms_text)
        merchant_match = re.search(merchant_pattern, sms_text, re.IGNORECASE)
        date_match = re.search(date_pattern, sms_text)
        
        logger.debug(f"Amount match: {amount_match.group(1) if amount_match else None}")
        logger.debug(f"Merchant match: {merchant_match.group(1) if merchant_match else None}")
        logger.debug(f"Date match: {date_match.group(1) if date_match else None}")
        
        # Parse the message
        parsed_data = parse_sms(sms_text)
        logger.debug(f"Parsed data: {parsed_data}")
        
        return jsonify({
            'success': True,
            'debug_info': {
                'amount_match': amount_match.group(1) if amount_match else None,
                'merchant_match': merchant_match.group(1) if merchant_match else None,
                'date_match': date_match.group(1) if date_match else None,
                'parsed_data': parsed_data
            }
        })
        
    except Exception as e:
        logger.error(f"Error in test_parse: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Helper functions
def get_account_name(account_id):
    return ACCOUNT_MAPPING.get(account_id, account_id)

# Add this new route after the existing routes
@app.route('/delete_entry', methods=['POST'])
@login_required
def delete_entry():
    try:
        data = request.get_json()
        page_id = data.get('page_id')
        
        if not page_id:
            return jsonify({
                'success': False,
                'error': 'No page ID provided'
            }), 400

        headers = {
            'Authorization': f'Bearer {NOTION_API_KEY}',
            'Notion-Version': '2022-06-28'
        }

        # Archive the page in Notion (soft delete)
        response = requests.patch(
            f'https://api.notion.com/v1/pages/{page_id}',
            headers=headers,
            json={
                'archived': True
            }
        )

        if response.status_code != 200:
            logger.error(f"Notion API error: {response.status_code} - {response.text}")
            return jsonify({
                'success': False,
                'error': f'Failed to delete entry: {response.text}'
            }), 500

        return jsonify({
            'success': True,
            'message': 'Entry deleted successfully'
        })

    except Exception as e:
        logger.error(f"Error deleting entry: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    try:
        # Get local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        print(f"\nTo access the application from your mobile device:")
        print(f"1. Make sure your mobile device is connected to the same WiFi network as this computer")
        print(f"2. Open your mobile browser and go to: http://{local_ip}:8080")
        print(f"3. Scan the QR code at: http://{local_ip}:8080/qr")
        print(f"\nIf you can't connect, try these troubleshooting steps:")
        print(f"1. Check if your mobile device is on the same WiFi network")
        print(f"2. Try accessing the app from your computer's browser at http://localhost:8080")
        print(f"3. Make sure no other application is using port 8080")
        
        # Run the app without SSL for local development
        app.run(host='0.0.0.0', port=8080, debug=True)
    except Exception as e:
        print(f"\nError starting the application: {str(e)}")
        print("Please make sure no other application is using port 8080") 