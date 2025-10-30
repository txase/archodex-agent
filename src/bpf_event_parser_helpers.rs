macro_rules! field_offset {
    ($t:ident :: $( $field:ident )::+) => {{
        let c = std::mem::MaybeUninit::uninit();
        let c_ptr: *const $t = c.as_ptr();

        unsafe {
            // cast to u8 pointers so we get offset in bytes
            let c_u8_ptr = c_ptr.cast::<u8>();
            let f_u8_ptr = (&raw const (*c_ptr).$( $field ).+).cast::<u8>();

            f_u8_ptr.offset_from_unsigned(c_u8_ptr)
        }
    }};
}

macro_rules! field_size {
    ($t:ident :: $( $field:ident )::+) => {{
        const fn size_of_raw<T>(_: *const T) -> usize {
            core::mem::size_of::<T>()
        }

        let m = core::mem::MaybeUninit::<$t>::uninit();
        let p = unsafe { (&raw const (*(&raw const m).cast::<$t>()).$( $field ).+) };

        size_of_raw(p)
    }};
}

macro_rules! field_byte_slice {
    ($data:ident, $( $field:ident )::+) => {{
        &$data[field_offset!($( $field )::+)..field_offset!($( $field )::+) + field_size!($( $field )::+)]
    }};
}

macro_rules! field_to_event_end_byte_slice {
    ($data:ident, $( $field:ident )::+) => {{
        &$data[field_offset!($( $field )::+)..]
    }};
}

pub(crate) use field_byte_slice;
pub(crate) use field_offset;
pub(crate) use field_size;
pub(crate) use field_to_event_end_byte_slice;
