use std::{
    io,
    mem::size_of,
    ops::{AddAssign, Range},
};

use elf::{ParseError, endian::EndianParse, file::Class, parse::ParseAt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerSize {
    Four,
    Eight,
}

impl TryFrom<u8> for PointerSize {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            4 => Ok(PointerSize::Four),
            8 => Ok(PointerSize::Eight),
            ptr_size => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Pointer size invalid value {ptr_size}"),
            )),
        }
    }
}

impl AddAssign<PointerSize> for usize {
    fn add_assign(&mut self, rhs: PointerSize) {
        match rhs {
            PointerSize::Four => *self += 4,
            PointerSize::Eight => *self += 8,
        }
    }
}

/// Header at the start of a GO PC Line Table section
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoPCLineTableHeader {
    pub magic: u32,
    pub pc_quantum: u8,
    pub ptr_size: PointerSize,
}

impl ParseAt for GoPCLineTableHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let magic = endian.parse_u32_at(offset, data)?;
        if magic != 0xFFFF_FFF1 {
            return Err(ParseError::BadMagic(magic.to_ne_bytes()));
        }

        let zero = endian.parse_u16_at(offset, data)?;
        if zero != 0 {
            return Err(ParseError::IOError(io::Error::new(
                io::ErrorKind::InvalidData,
                "Bytes 5 and 6 were not zero",
            )));
        }

        let pc_quantum = endian.parse_u8_at(offset, data)?;
        if !matches!(pc_quantum, 1 | 2 | 4) {
            return Err(ParseError::IOError(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("PC quantum invalid value {pc_quantum}"),
            )));
        }

        let ptr_size = endian.parse_u8_at(offset, data)?.try_into()?;

        Ok(Self {
            magic,
            pc_quantum,
            ptr_size,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        size_of::<u32>() + size_of::<u16>() + size_of::<u8>() + size_of::<u8>()
    }
}

#[derive(Debug)]
pub struct GoPCLineTable<'data, E: EndianParse> {
    pub hdr: GoPCLineTableHeader,

    endian: E,
    class: Class,
    data: &'data [u8],
}

#[allow(clippy::struct_field_names)]
#[derive(Default)]
struct GoSymbolRangesInternal {
    go_tls_handshake_context: Option<Range<usize>>,
    go_tls_close: Option<Range<usize>>,
    go_tls_read: Option<Range<usize>>,
    go_tls_write: Option<Range<usize>>,
}

#[allow(clippy::struct_field_names)]
pub(crate) struct GoSymbolRanges {
    pub(crate) go_tls_handshake_context: Range<usize>,
    pub(crate) go_tls_close: Range<usize>,
    pub(crate) go_tls_read: Range<usize>,
    pub(crate) go_tls_write: Range<usize>,
}

impl<'data, E: EndianParse> GoPCLineTable<'data, E> {
    /// Construct a `GoPCLineTable` from given bytes. Keeps a reference to the data for lazy parsing.
    pub fn new(endian: E, class: Class, data: &'data [u8]) -> Result<Self, ParseError> {
        let mut offset = 0;
        let hdr = GoPCLineTableHeader::parse_at(endian, class, &mut offset, data)?;

        Ok(Self {
            hdr,
            endian,
            class,
            data,
        })
    }

    fn read_field(&self, offset: &mut usize) -> Result<u64, ParseError> {
        match self.hdr.ptr_size {
            PointerSize::Four => self
                .endian
                .parse_u32_at(offset, self.data)
                .map(std::convert::Into::into),
            PointerSize::Eight => self.endian.parse_u64_at(offset, self.data),
        }
    }

    pub fn find_go_tls_symbols(&self) -> anyhow::Result<Option<GoSymbolRanges>> {
        let mut offset = GoPCLineTableHeader::size_for(self.class);

        let nfunctab = self.read_field(&mut offset)?;
        offset += self.hdr.ptr_size; // nfiletab
        offset += self.hdr.ptr_size; // textstart
        let funcnametab_offset = self.read_field(&mut offset)?.try_into()?;
        let funcnametab = &self.data[funcnametab_offset..];
        offset += self.hdr.ptr_size; // cutab_offset
        offset += self.hdr.ptr_size; // filetab_offset
        offset += self.hdr.ptr_size; // pctab_offset
        let funcdata_offset = self.read_field(&mut offset)?.try_into()?;
        let funcdata = &self.data[funcdata_offset..];
        let functab = funcdata;

        let mut symbols = GoSymbolRangesInternal::default();

        let mut none = None;
        let mut cur_symbol: &mut Option<Range<usize>> = &mut none;
        for i in 0..nfunctab {
            // functab fields are always size 4 starting with Go 1.18.
            const FUNCTAB_FIELD_SIZE: u64 = 4;

            //Entries start offset by 4 bytes, and include two fields per entry.
            let mut functab_func_offset =
                (FUNCTAB_FIELD_SIZE + i * 2 * FUNCTAB_FIELD_SIZE).try_into()?;
            let funcdata_offset = self
                .endian
                .parse_u32_at(&mut functab_func_offset, functab)?
                .try_into()?;

            let funcdata_func = &funcdata[funcdata_offset..];
            let mut funcdata_offset = 0;

            let pc = self
                .endian
                .parse_u32_at(&mut funcdata_offset, funcdata_func)?;

            if let Some(symbol) = cur_symbol {
                symbol.end = pc.try_into()?;

                if symbols.go_tls_handshake_context.is_some()
                    && symbols.go_tls_close.is_some()
                    && symbols.go_tls_read.is_some()
                    && symbols.go_tls_write.is_some()
                {
                    return Ok(Some(GoSymbolRanges {
                        go_tls_handshake_context: symbols.go_tls_handshake_context.unwrap(),
                        go_tls_close: symbols.go_tls_close.unwrap(),
                        go_tls_read: symbols.go_tls_read.unwrap(),
                        go_tls_write: symbols.go_tls_write.unwrap(),
                    }));
                }
            }

            let nameoff = self
                .endian
                .parse_u32_at(&mut funcdata_offset, funcdata_func)?
                .try_into()?;

            let name_end = nameoff
                + funcnametab[nameoff..]
                    .iter()
                    .position(|&c| c == b'\0')
                    .ok_or(ParseError::StringTableMissingNul(nameoff as u64))?;

            cur_symbol = match &funcnametab[nameoff..name_end] {
                b"crypto/tls.(*Conn).handshakeContext" => {
                    symbols.go_tls_handshake_context = Some(pc.try_into()?..pc.try_into()?);
                    &mut symbols.go_tls_handshake_context
                }
                b"crypto/tls.(*Conn).Close" => {
                    symbols.go_tls_close = Some(pc.try_into()?..pc.try_into()?);
                    &mut symbols.go_tls_close
                }
                b"crypto/tls.(*Conn).Read" => {
                    symbols.go_tls_read = Some(pc.try_into()?..pc.try_into()?);
                    &mut symbols.go_tls_read
                }
                b"crypto/tls.(*Conn).Write" => {
                    symbols.go_tls_write = Some(pc.try_into()?..pc.try_into()?);
                    &mut symbols.go_tls_write
                }
                _ => &mut none,
            };
        }

        Ok(None)
    }
}
