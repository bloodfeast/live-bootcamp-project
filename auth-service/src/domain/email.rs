use std::str::FromStr;
use color_eyre::eyre::{eyre, Result};
use crate::domain::{AuthAPIError, FromDbString};

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Email {
    email: String,
}


impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.email
    }
}
impl FromStr for Email {
    type Err = AuthAPIError;

    /// ###### Slight deviation from the course material
    /// Implemented `FromStr` trait for `Email`. \
    /// This approach just feels more ergonomic to me,
    /// but it's really personal preference.
    ///
    /// ##### Arguments
    /// * `s` - A string slice that holds the email
    ///
    /// ##### Returns
    /// A `Result` containing a `Email` instance if the string is a valid email,
    /// otherwise an `InvalidCredentials` error.
    ///
    /// # Examples
    /// ```
    /// use std::str::FromStr;
    /// use auth_service::domain::Email;
    /// use auth_service::domain::AuthAPIError;
    ///
    /// let email = Email::from_str("some.email@domain.com");
    /// assert!(email.is_ok());
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        let is_valid = !s.is_empty() && validator::ValidateEmail::validate_email(&s);
        if !is_valid {
            return eyre!(AuthAPIError::InvalidCredentials);
        };
        Ok(Email {
            email: s.to_string(),
        })
    }
}

impl FromDbString for Email {
    fn from_db_string(s: &str) -> Self {
        Email {
            email: s.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::Email;

    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::Arbitrary;

    #[test]
    fn empty_string_is_rejected() {
        let email = "";
        assert!(Email::from_str(email).is_err());
    }
    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = "ursuladomain.com";
        assert!(Email::from_str(email).is_err());
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        let email = "@domain.com";
        assert!(Email::from_str(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl Arbitrary for ValidEmailFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let email = SafeEmail().fake_with_rng(g);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::from_str(valid_email.0.as_str()).is_ok()
    }
}
