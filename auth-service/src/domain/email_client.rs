use super::Email;

#[async_trait::async_trait]
pub trait EmailClient
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String>;
}