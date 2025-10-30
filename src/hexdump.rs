use std::fmt::Write as _;

pub(crate) trait HexDump {
    fn to_hexdump(&self) -> String;
}

impl HexDump for &[u8] {
    fn to_hexdump(&self) -> String {
        if self.is_empty() {
            return "[]".to_string();
        }

        let mut hexdump = String::new();

        let num_rows = self.len().div_ceil(0x10);

        for i in 0..num_rows {
            let index = i * 0x10;

            write!(&mut hexdump, "\t{index:08x}  ")
                .expect("Failed to write prefix to hexdump buffer");

            for j in index..(index + 8) {
                if j < self.len() {
                    write!(&mut hexdump, "{:02x} ", self[j])
                        .expect("Failed to write byte to hexdump buffer");
                } else {
                    hexdump.push_str("   ");
                }
            }

            hexdump.push(' ');

            for j in (index + 8)..(index + 16) {
                if j < self.len() {
                    write!(&mut hexdump, "{:02x} ", self[j])
                        .expect("Failed to write byte to hexdump buffer");
                } else {
                    hexdump.push_str("   ");
                }
            }

            hexdump.push_str(" |");

            for j in index..(index + 16) {
                if j < self.len() {
                    match self[j] {
                        32..=126 => hexdump.push(self[j] as char),
                        _ => hexdump.push('.'),
                    }
                } else {
                    hexdump.push(' ');
                }
            }

            hexdump.push('|');

            if i < num_rows - 1 {
                hexdump.push('\n');
            }
        }

        hexdump
    }
}

impl HexDump for [u8] {
    fn to_hexdump(&self) -> String {
        <&[u8]>::to_hexdump(&self)
    }
}

impl HexDump for Vec<u8> {
    fn to_hexdump(&self) -> String {
        self.as_slice().to_hexdump()
    }
}

pub(crate) struct DebugVecU8<'a>(pub(crate) &'a Vec<u8>);

impl std::fmt::Debug for DebugVecU8<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_hexdump())
    }
}

impl<'a> From<&'a Vec<u8>> for DebugVecU8<'a> {
    fn from(value: &'a Vec<u8>) -> Self {
        DebugVecU8(value)
    }
}
