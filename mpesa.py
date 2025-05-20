import requests
from requests.auth import HTTPBasicAuth
import base64
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

consumer_key = os.getenv("CONSUMER_KEY")
consumer_secret = os.getenv("CONSUMER_SECRET")
shortcode = os.getenv("BUSINESS_SHORTCODE")
passkey = os.getenv("PASSKEY")

# Debug logging
print("Environment Variables:")
print(f"CONSUMER_KEY: {consumer_key}")
print(f"CONSUMER_SECRET: {consumer_secret}")
print(f"BUSINESS_SHORTCODE: {shortcode}")
print(f"PASSKEY: {passkey}")

def get_access_token():
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    print("\nAccess Token Response:")
    print(response.text)
    access_token = response.json().get("access_token")
    return access_token

def lipa_na_mpesa(phone_number, amount):
    access_token = get_access_token()
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    data_to_encode = shortcode + passkey + timestamp
    password = base64.b64encode(data_to_encode.encode()).decode("utf-8")
    
    print("\nRequest Details:")
    print(f"Timestamp: {timestamp}")
    print(f"Password (base64): {password}")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": shortcode,
        "PhoneNumber": phone_number,
        "CallBackURL": "https://mydomain.com/path",  # Dummy URL for sandbox
        "AccountReference": "QpidTest",
        "TransactionDesc": "Payment for service"
    }

    response = requests.post(
        "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        json=payload,
        headers=headers
    )
    return response.json()
