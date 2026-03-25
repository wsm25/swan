use anyhow::{Result, bail, ensure};

pub(crate) fn verify_presented_identity(
    expected_aaa_identity: &str,
    dns_sans: &[String],
    common_name: Option<&str>,
) -> Result<()> {
    let expected = normalize_expected(expected_aaa_identity)?;
    if dns_sans.iter().any(|name| name_matches(&expected, name)) {
        return Ok(());
    }
    if let Some(common_name) = common_name
        && name_matches(&expected, common_name)
    {
        return Ok(());
    }
    bail!("aaa identity mismatch: expected {expected}");
}

fn normalize_expected(value: &str) -> Result<String> {
    let trimmed = value.trim();
    ensure!(!trimmed.is_empty(), "aaa identity must not be empty");
    let normalized = normalize_name(trimmed.trim_start_matches('@'));
    ensure!(!normalized.is_empty(), "aaa identity must not be empty");
    Ok(normalized)
}

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn name_matches(expected: &str, candidate: &str) -> bool {
    let candidate = normalize_name(candidate);
    if expected.contains('*') || expected.contains('?') {
        return wildcard_match(expected, &candidate);
    }
    candidate == expected
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0usize, 0usize);
    let (mut star_pattern_index, mut star_value_index) = (None, 0usize);
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
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
