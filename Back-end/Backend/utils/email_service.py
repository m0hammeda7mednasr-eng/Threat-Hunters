import os
import requests

from dotenv import load_dotenv

load_dotenv()


def send_email(to_email, subject, body):
    print("SEND_EMAIL CALLED")
    print("TO:", to_email)

    api_key = os.getenv("RESEND_API_KEY")

    if not api_key:
        print("RESEND_API_KEY not found")
        return False

    try:

        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": "noreply@threathunterseg.com",
                "to": [to_email],
                "subject": subject,
                "text": body,
            },
            timeout=30,
        )

        print("RESEND STATUS:", response.status_code)
        print("RESEND RESPONSE:", response.text)

        return response.status_code in [200, 201]

    except Exception as e:

        print("EMAIL ERROR:", e)

        return False