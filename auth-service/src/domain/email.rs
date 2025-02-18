use std::hash::Hash;
use std::str::FromStr;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use crate::domain::{AuthAPIError, FromDbString};

#[derive(Debug, Clone)]
pub struct Email {
    email: Secret<String>,
}

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Self> {
        if !validator::ValidateEmail::validate_email(&s.expose_secret()) {
            Err(eyre!(AuthAPIError::InvalidCredentials))
        } else {
            Ok(Email {
                email: s,
            })
        }
    }
}

impl Eq for Email {}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.email.expose_secret().to_owned() == other.email.expose_secret().to_owned()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.expose_secret().to_owned().hash(state);
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.email
    }
}

impl FromDbString for Email {
    fn from_db_string(s: &str) -> Self {
        Email {
            email: Secret::new(s.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::Arbitrary;
    use secrecy::Secret;

    #[test]
    fn empty_string_is_rejected() {
        let email = Secret::new("".to_string());
        assert!(Email::parse(email).is_err());
    }
    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = Secret::new("ursuladomain.com".to_string());
        assert!(Email::parse(email).is_err());
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        let email = Secret::new("@domain.com".to_string());
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let email = SafeEmail().fake_with_rng(g);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(Secret::new(valid_email.0)).is_ok() // Updated!
    }
}
