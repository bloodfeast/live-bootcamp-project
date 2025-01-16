use std::str::FromStr;
use crate::domain::AuthAPIError;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Email {
    email: String,
    is_valid: bool,
}


impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.email
    }
}
impl FromStr for Email {
    type Err = AuthAPIError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_valid = !s.is_empty() && validator::ValidateEmail::validate_email(&s);
        if !is_valid {
            return Err(AuthAPIError::InvalidCredentials);
        };
        Ok(Email {
            email: s.to_string(),
            is_valid
        })
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
