import os
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from dotenv import load_dotenv

load_dotenv()


def send_email(to_email, subject, body):

    email_address = os.getenv("EMAIL_ADDRESS")
    email_password = os.getenv("EMAIL_PASSWORD")

    message = MIMEMultipart()

    message["From"] = email_address
    message["To"] = to_email
    message["Subject"] = subject

    message.attach(
        MIMEText(body, "plain")
    )

    try:

        server = smtplib.SMTP(
            "smtp.gmail.com",
            587
        )

        server.starttls()

        server.login(
            email_address,
            email_password
        )

        server.sendmail(
            email_address,
            to_email,
            message.as_string()
        )

        server.quit()

        return True

    except Exception as e:

        print("EMAIL ERROR:", e)

        return False