from mpesa import lipa_na_mpesa

def main():
    # Test phone number (replace with actual phone number in international format)
    phone_number = "254790477329"  # Example: 254XXXXXXXXX
    amount = "10"  # Amount in KES
    
    try:
        response = lipa_na_mpesa(phone_number, amount)
        print("M-Pesa STK Push Response:")
        print(response)
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()
