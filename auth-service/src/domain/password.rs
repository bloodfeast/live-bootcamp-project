use std::hash::Hash;
use std::str::FromStr;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use crate::domain::{AuthAPIError, FromDbString};

#[derive(Debug, Clone)]
pub struct Password {
    password: Secret<String>,
}

impl Eq for Password {}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.password.expose_secret() == other.password.expose_secret()
    }
}

impl Hash for Password {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.password.expose_secret().hash(state);
    }
}

impl Password {
    pub fn parse(s: Secret<String>) -> Result<Self> {
        let is_valid = validate_password(&s);

        if !is_valid {
            return Err(eyre!(AuthAPIError::InvalidCredentials));
        };

        Ok(Password {
            password: s,
        })
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String>{
        &self.password
    }
}

impl FromDbString for Password {
    fn from_db_string(s: &str) -> Self {
        Password {
            password: Secret::new(s.to_string()),
        }
    }
}

fn validate_password(password: &Secret<String>) -> bool {
    let password = password.expose_secret();
    let length_check = validator::ValidateLength::validate_length(password, Some(8), Some(32), None);
    if !length_check {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use secrecy::Secret;

    #[test]
    fn empty_string_is_rejected() {
        let password = Secret::new("".to_string());
        assert!(Password::parse(password).is_err());
    }
    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = Secret::new("1234567".to_string());
        assert!(Password::parse(password).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let password = FakePassword(8..30).fake_with_rng(g);
            Self(password)
        }
    }
    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(Secret::new(valid_password.0)).is_ok()
    }
}