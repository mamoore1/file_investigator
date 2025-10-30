## File Investigator

A simple Flask app allowing for reputation checks on IP Addresses and file hashes.

Set up with:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run the Flask development server on localhost:5000 using `python run.py`. Place AbuseIPDB and VirusTotal API keys in a .env file in the top-level directory (where they will be loaded by `dotenv`). IPs can be investigated at the `/check-ip` endpoint and VirusTotal file reports can be accessed using the `/file-report` endpoint.

### To-Do
- Access the MITRE ATT&CK information on Tools, Techniques and Procedures for provided file hashes
- Check for any files associated with a provided IP address
