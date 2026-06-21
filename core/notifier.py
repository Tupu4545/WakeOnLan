"""Email notification notifier using SMTP."""

import smtplib
import logging
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Manages transactional SMTP email alerts for bot status and device actions."""

    def __init__(self, config):
        self.config = config

    def send_alert(self, subject: str, body: str) -> bool:
        """Send an email alert using SMTP configuration from environment."""
        if not self.config.email_alerts_enabled:
            logger.debug("Email alerts are disabled, skipping notification.")
            return False

        if not all([self.config.email_smtp_server, self.config.email_sender,
                    self.config.email_receiver, self.config.email_smtp_password]):
            logger.error("Email notification configured as enabled, but missing SMTP parameters.")
            return False

        try:
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = f"[WakeOnLan Bot] {subject}"
            msg['From'] = self.config.email_sender
            msg['To'] = self.config.email_receiver

            server = None
            try:
                # Use SMTP_SSL for port 465, standard SMTP for other ports
                if self.config.email_smtp_port == 465:
                    server = smtplib.SMTP_SSL(self.config.email_smtp_server, self.config.email_smtp_port, timeout=10)
                else:
                    server = smtplib.SMTP(self.config.email_smtp_server, self.config.email_smtp_port, timeout=10)
                    if self.config.email_smtp_port == 587:
                        server.ehlo()
                        server.starttls()
                        server.ehlo()

                server.login(self.config.email_sender, self.config.email_smtp_password)
                server.sendmail(self.config.email_sender, [self.config.email_receiver], msg.as_string())
                logger.info(f"Email alert sent successfully: {subject}")
                return True
            finally:
                if server:
                    try:
                        server.quit()
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}", exc_info=True)
            return False
