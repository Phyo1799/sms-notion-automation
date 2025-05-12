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

4. Open your browser and navigate to:
   - `http://localhost:8080` to access the application from the same computer.
   - Use the local WiFi IP address (e.g., `http://<local_ip>:8080`) to access the application from other devices on the same WiFi network.

## Usage

1. Copy your SMS message.
2. Paste it into the text area on the website.
3. Click "Add to Notion".
4. The transaction will be automatically added to your Notion database.

## Features

- Automatically extracts:
  - Transaction amount (always positive)
  - Merchant name (extracted from the SMS format)
  - Transaction date
- User authentication with secure login/logout functionality.
- QR code generation for easy access from mobile devices.
- Integration with Notion API to add transactions directly to your Notion database.
- Comprehensive error handling and logging for debugging.
- CSV export functionality to download transaction data.
- Modern, responsive UI with real-time feedback on success/failure.
- Testing route for debugging SMS parsing.

## Troubleshooting

- Ensure your mobile device is connected to the same WiFi network as your computer to access the application via the generated QR code.
- If you encounter issues, check that no other application is using port 8080.
