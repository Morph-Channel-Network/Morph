//! Canonical public transport scalars. Core signing encodings remain separate.
pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    /// Exact canonical u64 string schema, including the upper bound. JSON number
    /// maxima would not constrain a string and would invite precision loss.
    pub fn schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schema_for_max(u64::MAX.to_string())
    }
    pub(super) fn schema_for_max(maximum: String) -> schemars::Schema {
        let digits = maximum.len();
        let mut alternatives = vec![
            "0".to_owned(),
            format!("[1-9][0-9]{{0,{}}}", digits - 2),
            maximum.clone(),
        ];
        for (index, digit) in maximum.bytes().enumerate() {
            let lower = if index == 0 { b'1' } else { b'0' };
            if digit > lower {
                alternatives.push(format!(
                    "{}[{}-{}][0-9]{{{}}}",
                    &maximum[..index],
                    char::from(lower),
                    char::from(digit - 1),
                    maximum.len() - index - 1
                ));
            }
        }
        schemars::json_schema!({
            "type":"string", "minLength":1, "maxLength":digits,
            "not": {"pattern":"[^0-9]"},
            "pattern": format!("^({})$", alternatives.join("|")),
            "description":format!("Canonical unsigned decimal string in 0..={maximum}. Units are documented on the field.")
        })
    }
    pub fn parse(value: &str) -> Option<u64> {
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|b| b.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return None;
        }
        value.parse().ok()
    }
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        parse(&value)
            .ok_or_else(|| serde::de::Error::custom("expected canonical decimal u64 string"))
    }
}

pub mod optional_decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| {
                super::decimal::parse(&value).ok_or_else(|| {
                    serde::de::Error::custom("expected canonical decimal u64 string or null")
                })
            })
            .transpose()
    }
    pub fn schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "anyOf": [super::decimal::schema(generator), {"type":"null"}] })
    }
}

/// Full-width public token quantities; never converted through JSON numbers.
pub mod amount {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        super::decimal::schema_for_max(u128::MAX.to_string())
    }
    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let raw = String::deserialize(d)?;
        let value = raw
            .parse::<u128>()
            .map_err(|_| serde::de::Error::custom("expected canonical decimal u128 string"))?;
        if value.to_string() != raw {
            return Err(serde::de::Error::custom(
                "expected canonical decimal u128 string",
            ));
        }
        Ok(value)
    }
}
