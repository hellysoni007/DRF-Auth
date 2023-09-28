from django.core.mail import EmailMessage
import os


class Util:
    @staticmethod
    def send_mail(data):
        print("Utils started")
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=os.environ.get('EMAIL_USER'),
            to=[data['to_email']]
        )
        email.send()

