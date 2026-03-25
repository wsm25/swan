use super::Ikev2Routine;
use crate::consts::{ID_TYPE_DER_ASN1_DN, ID_TYPE_FQDN, ID_TYPE_RFC822_ADDR};

pub(super) fn rightid_matches(expected: &str, received_type: u8, received_id: &[u8]) -> bool {
    fn wildcard_match(pattern: &str, value: &str, case_insensitive: bool) -> bool {
        fn eq_byte(a: u8, b: u8, case_insensitive: bool) -> bool {
            if case_insensitive { a.eq_ignore_ascii_case(&b) } else { a == b }
        }

        let pattern = pattern.as_bytes();
        let value = value.as_bytes();
        let (mut pattern_index, mut value_index) = (0usize, 0usize);
        let (mut star_pattern_index, mut star_value_index) = (None, 0usize);
        while value_index < value.len() {
            if pattern_index < pattern.len()
                && (pattern[pattern_index] == b'?'
                    || eq_byte(pattern[pattern_index], value[value_index], case_insensitive))
            {
                pattern_index += 1;
                value_index += 1;
                continue;
            }
            if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
                star_pattern_index = Some(pattern_index);
                pattern_index += 1;
                star_value_index = value_index;
                continue;
            }
            if let Some(previous_star_index) = star_pattern_index {
                pattern_index = previous_star_index + 1;
                star_value_index += 1;
                value_index = star_value_index;
                continue;
            }
            return false;
        }
        while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            pattern_index += 1;
        }
        pattern_index == pattern.len()
    }

    let (expected_type, expected_value) = Ikev2Routine::configured_id_type_and_value(expected);
    if expected_type != received_type {
        return false;
    }
    if expected_type == ID_TYPE_DER_ASN1_DN {
        let Ok(expected_id) = Ikev2Routine::encoded_id_value(expected_type, expected_value) else {
            return false;
        };
        return expected_id.as_ref() == received_id;
    }
    let case_insensitive = matches!(expected_type, ID_TYPE_FQDN | ID_TYPE_RFC822_ADDR);
    if expected_value.contains('*') || expected_value.contains('?') {
        let Ok(received) = std::str::from_utf8(received_id) else {
            return false;
        };
        return wildcard_match(expected_value, received, case_insensitive);
    }
    let Ok(received) = std::str::from_utf8(received_id) else {
        return !case_insensitive && expected_value.as_bytes() == received_id;
    };
    if case_insensitive {
        expected_value.eq_ignore_ascii_case(received)
    } else {
        expected_value.as_bytes() == received_id
    }
}
