# SMS to Notion

A web application that allows you to paste SMS messages and automatically add them to your Notion database.

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file in the root directory with the following content:
```
NOTION_API_KEY=your_notion_api_key_here
DATABASE_ID=your_database_id_here
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Copy your SMS message
2. Paste it into the text area on the website
3. Click "Add to Notion"
4. The transaction will be automatically added to your Notion database

## Features

- Automatically extracts:
  - Transaction amount
  - Merchant name
  - Transaction date
- Modern, responsive UI
- Real-time feedback on success/failure
- Secure API key handling 