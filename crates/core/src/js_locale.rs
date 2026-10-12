//! Historical protocol ordering uses the pinned Node 24 / ICU 78.3 en-US
//! collation over original UTF-16 code units, including lone surrogates.

use std::{
    cmp::Ordering,
    ffi::{c_char, c_void},
    sync::OnceLock,
};

#[repr(align(16))]
struct AlignedData<const N: usize>([u8; N]);

static ICU_DATA: AlignedData<2_086_192> = AlignedData(*include_bytes!(
    "../../../third_party/icu4c-78.3/icudt78l.dat"
));

unsafe extern "C" {
    #[link_name = "udata_setFileAccess_78_peerwork"]
    fn set_file_access(access: i32, error: *mut i32);
    #[link_name = "udata_setCommonData_78_peerwork"]
    fn set_common_data(data: *const c_void, error: *mut i32);
    #[link_name = "ucol_open_78_peerwork"]
    fn open_collator(locale: *const c_char, error: *mut i32) -> *mut c_void;
    #[link_name = "ucol_strcoll_78_peerwork"]
    fn compare_collation(
        collator: *const c_void,
        left: *const u16,
        left_len: i32,
        right: *const u16,
        right_len: i32,
    ) -> i32;
    #[link_name = "ucol_close_78_peerwork"]
    fn close_collator(collator: *mut c_void);
}

fn initialize() {
    static INITIALIZED: OnceLock<()> = OnceLock::new();
    INITIALIZED.get_or_init(|| unsafe {
        // UDATA_NO_FILES = 3 in the pinned ICU 78.3 udata.h.
        let mut error = 0;
        set_file_access(3, &mut error);
        assert!(error <= 0, "pinned ICU file-access initialization: {error}");
        error = 0;
        set_common_data(ICU_DATA.0.as_ptr().cast(), &mut error);
        assert!(
            error <= 0,
            "pinned ICU embedded data initialization: {error}"
        );
    });
}

pub(crate) fn locale_compare_utf16(left: &[u16], right: &[u16]) -> Ordering {
    initialize();
    let left_len = i32::try_from(left.len()).expect("protocol key length is bounded");
    let right_len = i32::try_from(right.len()).expect("protocol key length is bounded");
    let mut error = 0;
    let collator = unsafe { open_collator(c"en_US".as_ptr(), &mut error) };
    assert!(
        !collator.is_null() && error <= 0,
        "pinned ICU collator open: {error}"
    );
    let result =
        unsafe { compare_collation(collator, left.as_ptr(), left_len, right.as_ptr(), right_len) };
    unsafe { close_collator(collator) };
    result.cmp(&0)
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
        assert_eq!(
            vectors
                .get("node")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("24.20.0")
        );
        assert_eq!(
            vectors.get("icu").and_then(WireValue::as_string).as_deref(),
            Some("78.3")
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
