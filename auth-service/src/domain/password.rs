use std::str::FromStr;
use crate::domain::AuthAPIError;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Password {
    password: String,
    is_valid: bool,
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.password
    }
}

impl FromStr for Password {
    type Err = AuthAPIError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_valid = validate_password(&s);

        if !is_valid {
            return Err(AuthAPIError::InvalidCredentials);
        };

        Ok(Password {
            password: s.to_string(),
            is_valid
        })
    }
}


fn validate_password(password: &str) -> bool {
    let length_check = validator::ValidateLength::validate_length(password, Some(8), Some(32), None);
    if !length_check {
        return false;
    }
    let valid_chars = validator::ValidateNonControlCharacter::validate_non_control_character(&password);
    if !valid_chars {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;

    #[test]
    fn empty_string_is_rejected() {
        let password = "";
        assert!(Password::from_str(password).is_err());
    }
    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = "1234567";
        assert!(Password::from_str(password).is_err());
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
        Password::from_str(valid_password.0.as_str()).is_ok()
    }
}