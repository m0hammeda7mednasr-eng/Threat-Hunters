from email_validator import (
    validate_email,
    EmailNotValidError
)

def validate_email_format(email):

    try:

        validate_email(
            email,
            check_deliverability=False
        )

        return True

    except EmailNotValidError:

        return False
