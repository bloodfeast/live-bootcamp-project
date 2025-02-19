use secrecy::ExposeSecret;
use crate::domain::{Email, EmailClient};

#[derive(Clone, Debug, Default)]
pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        println!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref().expose_secret().to_string(),
            subject,
            content
        );

        Ok(())
    }
}