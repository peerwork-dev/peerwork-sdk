//! Locale ordering used by the tracked Node 24 historical protocol composer.
//! The baseline's default locale is en-US; changing that baseline is a wire
//! compatibility change because sorted action arrays enter signed digests.

use icu_collator::{options::CollatorOptions, Collator, CollatorBorrowed};
use icu_locale::locale;
use std::{cmp::Ordering, sync::OnceLock};

fn collator() -> &'static CollatorBorrowed<'static> {
    static COLLATOR: OnceLock<CollatorBorrowed<'static>> = OnceLock::new();
    COLLATOR.get_or_init(|| {
        Collator::try_new(locale!("en-US").into(), CollatorOptions::default())
            .expect("compiled en-US collation data")
    })
}

fn has_unpaired_surrogate(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xd800..=0xdbff).contains(&unit) {
            if units
                .get(index + 1)
                .is_some_and(|next| (0xdc00..=0xdfff).contains(next))
            {
                index += 2;
                continue;
            }
            return true;
        }
        if (0xdc00..=0xdfff).contains(&unit) {
            return true;
        }
        index += 1;
    }
    false
}

pub(crate) fn locale_compare_utf16(left: &[u16], right: &[u16]) -> Ordering {
    let ordering = collator().compare_utf16(left, right);
    if ordering == Ordering::Equal
        && (has_unpaired_surrogate(left) || has_unpaired_surrogate(right))
    {
        // ICU4X replaces ill-formed code units before comparison, whereas
        // Node's ICU 78 still distinguishes them at the final collation level.
        left.cmp(right)
    } else {
        ordering
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::{parse_wire_json_bounded, WireValue};

    #[test]
    fn pinned_node_locale_compare_vectors() {
        let vectors = parse_wire_json_bounded(
            include_bytes!("../../../conformance/locale-vectors.json"),
            16,
            32 * 1024,
        )
        .unwrap();
        assert_eq!(
            vectors
                .get("locale")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("en-US")
        );
        let WireValue::Array(cases) = vectors.get("cases").unwrap() else {
            panic!("cases must be an array")
        };
        for case in cases {
            let left = case.get("left").unwrap().as_utf16().unwrap();
            let right = case.get("right").unwrap().as_utf16().unwrap();
            let sign = case.get("sign").unwrap().as_number().unwrap() as i32;
            let actual = match locale_compare_utf16(left, right) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            };
            assert_eq!(actual, sign, "left={left:?} right={right:?}");
        }
    }
}
