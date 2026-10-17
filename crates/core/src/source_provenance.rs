//! Strict validators for opt-in, untrusted source-document provenance.
//! Source timestamps are claims and remain distinct from Peerwork receipt time.

use crate::wire_json::WireValue;

pub(crate) fn valid_source_text(value: &WireValue) -> bool {
    value
        .as_utf16()
        // Match TextEncoder on the TS side: malformed UTF-16 is encoded with
        // replacement characters for the byte-length limit, while the original
        // wire units remain untouched in the record.
        .is_some_and(|units| String::from_utf16_lossy(units).len() <= 8_192)
}

pub(crate) fn valid_source_sha256(value: &WireValue) -> bool {
    value.as_string().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Match the TS parser's accepted strict RFC3339 subset: four-digit nonzero
/// year, explicit known offset, valid Gregorian calendar, no leap seconds and
/// one through nine fractional digits when a fraction is present.
pub(crate) fn valid_source_timestamp(value: &WireValue) -> bool {
    let Some(text) = value.as_string() else {
        return false;
    };
    valid_source_timestamp_str(&text)
}

pub(crate) fn valid_source_timestamp_str(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T') || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(&bytes[0..4]), number(&bytes[5..7]), number(&bytes[8..10]),
        number(&bytes[11..13]), number(&bytes[14..16]), number(&bytes[17..19]),
    ) else { return false };
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > month_days { return false; }

    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) { cursor += 1; }
        let digits = cursor - start;
        if !(1..=9).contains(&digits) { return false; }
    }
    match bytes.get(cursor..) {
        Some([b'Z']) => true,
        Some([sign @ (b'+' | b'-'), oh, oh2, b':', om, om2]) => {
            let Some(hours) = number(&[*oh, *oh2]) else { return false };
            let Some(minutes) = number(&[*om, *om2]) else { return false };
            !(hours > 23 || minutes > 59 || (*sign == b'-' && hours == 0 && minutes == 0))
        }
        _ => false,
    }
}

fn number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) { return None; }
    bytes.iter().try_fold(0u32, |n, byte| n.checked_mul(10)?.checked_add((byte - b'0') as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_time_matches_the_typescript_contract_edges() {
        for value in [
            "0001-01-01T00:00:00Z",
            "1500-02-28T23:59:59.123456789-04:30",
            "2000-02-29T12:00:00+23:59",
            "9999-12-31T23:59:59.1+00:01",
        ] { assert!(valid_source_timestamp_str(value), "{value}"); }
        for value in [
            "0000-01-01T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2001-02-29T00:00:00Z",
            "2000-02-30T00:00:00Z",
            "2000-01-01T24:00:00Z",
            "2000-01-01T00:60:00Z",
            "2000-01-01T00:00:60Z",
            "2000-01-01T00:00:00",
            "2000-01-01T00:00:00-00:00",
            "2000-01-01T00:00:00.1234567890Z",
            "2000-01-01T00:00:00+24:00",
            "2000-01-01T00:00:00+01:60",
        ] { assert!(!valid_source_timestamp_str(value), "{value}"); }
    }

    #[test]
    fn source_sha256_is_lowercase_hex_and_exactly_64_bytes() {
        assert!(valid_source_sha256(&WireValue::String("a".repeat(64).encode_utf16().collect())));
        assert!(!valid_source_sha256(&WireValue::String("A".repeat(64).encode_utf16().collect())));
        assert!(!valid_source_sha256(&WireValue::String("a".repeat(63).encode_utf16().collect())));
    }

    #[test]
    fn source_text_uses_utf8_byte_bound_and_textencoder_surrogate_behavior() {
        assert!(valid_source_text(&WireValue::String("a".repeat(8_192).encode_utf16().collect())));
        assert!(!valid_source_text(&WireValue::String("a".repeat(8_193).encode_utf16().collect())));
        assert!(valid_source_text(&WireValue::String("😀".repeat(2_048).encode_utf16().collect())));
        assert!(!valid_source_text(&WireValue::String("😀".repeat(2_049).encode_utf16().collect())));
        // TextEncoder replaces an unpaired surrogate with U+FFFD (three UTF-8
        // bytes) rather than rejecting the source claim.
        assert!(valid_source_text(&WireValue::String(vec![0xD800])));
        assert!(valid_source_text(&WireValue::String(vec![0xD800; 2_730])));
        assert!(!valid_source_text(&WireValue::String(vec![0xD800; 2_731])));
    }
}
