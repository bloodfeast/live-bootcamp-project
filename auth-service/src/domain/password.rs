use std::str::FromStr;
use crate::domain::AuthAPIError;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Password {
    password: String,
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.password
    }
}

impl FromStr for Password {
    type Err = AuthAPIError;

    /// Implemented `FromStr` trait for `Password`. \
    /// in the same fashion as [Email](crate::domain::Email::from_str)
    ///
    /// ##### Arguments
    /// * `s` - A string slice that holds the password
    ///
    /// ##### Returns
    /// A `Result` containing a `Password` instance if the string is a valid password,
    /// otherwise an `InvalidCredentials` error.
    ///
    /// ##### Examples
    /// ```
    /// use std::str::FromStr;
    /// use auth_service::domain::Password;
    /// use auth_service::domain::AuthAPIError;
    ///
    /// let password = Password::from_str("password123");
    /// assert!(password.is_ok());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_valid = validate_password(&s);

        if !is_valid {
            return Err(AuthAPIError::InvalidCredentials);
        };

        Ok(Password {
            password: s.to_string(),
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