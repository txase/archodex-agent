use std::{fs::File, ops::Range, sync::LazyLock};

use elf::{
    ElfStream, endian::AnyEndian, hash::GnuHashTable, parse::ParsingTable, section::SectionHeader,
    string_table::StringTable,
};
use regex::Regex;
use tracing::{debug, info, instrument, trace, warn};

use crate::gopclntab::GoPCLineTable;

#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub(crate) struct LibSSLAddresses {
    pub(crate) ssl_ctrl: usize,
    pub(crate) ssl_free: usize,
    pub(crate) ssl_read: Option<usize>,
    pub(crate) ssl_read_ex: Option<usize>,
    pub(crate) ssl_write: Option<usize>,
    pub(crate) ssl_write_ex: Option<usize>,
}

#[derive(Debug)]
pub(crate) struct GoVersion {
    pub(crate) major: u16,
    pub(crate) minor: u16,
}

#[derive(Debug)]
pub(crate) struct GoSymbolAddress {
    pub(crate) entry: usize,
    pub(crate) exits: Vec<usize>,
}

#[derive(Debug)]
pub(crate) struct GoTLSAddresses {
    pub(crate) go_version: GoVersion,
    pub(crate) handshake_context: GoSymbolAddress,
    pub(crate) close: GoSymbolAddress,
    pub(crate) read: GoSymbolAddress,
    pub(crate) write: GoSymbolAddress,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub(crate) struct RustlsAddresses {
    pub(crate) evp_aead_ctx_init_with_direction: usize,
    pub(crate) evp_aead_ctx_seal: usize,
    pub(crate) evp_aead_ctx_open: usize,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub(crate) struct RingAddresses {
    pub(crate) aes_hw_set_encrypt_key: usize,
    #[cfg(target_arch = "x86_64")]
    pub(crate) aesni_gcm_encrypt: usize,
    #[cfg(target_arch = "x86_64")]
    pub(crate) aesni_gcm_decrypt: usize,
    #[cfg(target_arch = "aarch64")]
    pub(crate) aes_gcm_enc_kernel: usize,
    #[cfg(target_arch = "aarch64")]
    pub(crate) aes_gcm_dec_kernel: usize,
    pub(crate) aes_hw_ctr32_encrypt_blocks: usize,
}

#[derive(Debug)]
pub(crate) enum SymbolAddresses {
    LibSSL(LibSSLAddresses),
    GoTLS(GoTLSAddresses),
    Rustls(RustlsAddresses),
    Ring(RingAddresses),
}

#[instrument]
pub(crate) fn find_symbol_addresses(path: &str) -> Option<SymbolAddresses> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            warn!(path, ?err, "Failed to open executable file");
            return None;
        }
    };

    let mut elf = match ElfStream::<elf::endian::AnyEndian, _>::open_stream(file) {
        Ok(elf) => elf,
        Err(err) => {
            debug!(?err, "Failed to parse executable file as ELF");
            return None;
        }
    };

    if let Some(addresses) = find_symbols_in_dynsym(&mut elf) {
        debug!(?addresses, "Found LibSSL addresses");
        return Some(addresses);
    }

    if let Some(addresses) = find_symbols_in_gopclntab(&mut elf) {
        debug!(?addresses, "Found GoTLS addresses");
        return Some(SymbolAddresses::GoTLS(addresses));
    }

    if let Some(addresses) = find_symbols_in_symtab(&mut elf) {
        debug!(?addresses, "Found LibSSL/Rustls/Ring addresses");
        return Some(addresses);
    }

    None
}

#[instrument(skip_all)]
fn find_symbols_in_dynsym(elf: &mut ElfStream<AnyEndian, File>) -> Option<SymbolAddresses> {
    const GNU_HASH_SECTION_NAME: &str = ".gnu.hash";

    let endianness = elf.ehdr.endianness;
    let class = elf.ehdr.class;
    let section_headers = elf.section_headers().to_owned();

    let gnu_hash_section_header = match elf.section_header_by_name(GNU_HASH_SECTION_NAME) {
        Ok(Some(hash)) => hash.to_owned(),
        Ok(None) => {
            debug!("{GNU_HASH_SECTION_NAME} section header does not exist");
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to find {GNU_HASH_SECTION_NAME} section in executable file"
            );
            return None;
        }
    };

    let gnu_hash_section_data = match elf.section_data(&gnu_hash_section_header) {
        Ok((data, None)) => data.to_owned(),
        Ok((_, Some(compression))) => {
            warn!(
                "{GNU_HASH_SECTION_NAME} section data is compressed with an unknown algorithm: {compression:#?}"
            );
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to get {GNU_HASH_SECTION_NAME} section data in executable file"
            );
            return None;
        }
    };

    let gnu_hash = match GnuHashTable::new(endianness, class, &gnu_hash_section_data) {
        Ok(gnu_hash) => gnu_hash,
        Err(err) => {
            warn!(
                ?err,
                "Failed to parse {GNU_HASH_SECTION_NAME} section in executable file"
            );
            return None;
        }
    };

    let (symbol_table, string_table) = match elf.dynamic_symbol_table() {
        Ok(Some(tables)) => tables,
        Ok(None) => {
            trace!("No SHT_DYNSYM section in executable file");
            return None;
        }
        Err(err) => {
            warn!(?err, "Failed to find SHT_DYNSYM section in executable file");
            return None;
        }
    };

    let ssl_ctrl = find_symbol_address_in_hash(
        &section_headers,
        &gnu_hash,
        &symbol_table,
        &string_table,
        "SSL_ctrl",
    )?;

    let ssl_free = find_symbol_address_in_hash(
        &section_headers,
        &gnu_hash,
        &symbol_table,
        &string_table,
        "SSL_free",
    )?;

    let ssl_read = find_symbol_address_in_hash(
        &section_headers,
        &gnu_hash,
        &symbol_table,
        &string_table,
        "SSL_read",
    );

    let ssl_read_ex = find_symbol_address_in_hash(
        &section_headers,
        &gnu_hash,
        &symbol_table,
        &string_table,
        "SSL_read_ex",
    );

    if ssl_read.is_some() || ssl_read_ex.is_some() {
        let ssl_write = find_symbol_address_in_hash(
            &section_headers,
            &gnu_hash,
            &symbol_table,
            &string_table,
            "SSL_write",
        );

        let ssl_write_ex = find_symbol_address_in_hash(
            &section_headers,
            &gnu_hash,
            &symbol_table,
            &string_table,
            "SSL_write_ex",
        );

        if ssl_write.is_some() || ssl_write_ex.is_some() {
            debug!("Found libssl symbols");
            return Some(SymbolAddresses::LibSSL(LibSSLAddresses {
                ssl_ctrl,
                ssl_free,
                ssl_read,
                ssl_read_ex,
                ssl_write,
                ssl_write_ex,
            }));
        }
    }

    None
}

#[instrument(
    level = "trace",
    skip(section_headers, hash, symbol_table, string_table)
)]
fn find_symbol_address_in_hash(
    section_headers: &[SectionHeader],
    hash: &GnuHashTable<AnyEndian>,
    symbol_table: &ParsingTable<AnyEndian, elf::symbol::Symbol>,
    string_table: &StringTable,
    sym: &str,
) -> Option<usize> {
    match hash.find(sym.as_bytes(), symbol_table, string_table) {
        Ok(Some((_, symbol))) => get_symbol_addr_from_symbol(section_headers, &symbol),
        Ok(None) => {
            trace!("Symbol not found");
            None
        }
        Err(err) => {
            warn!(?err, "Failed to search for symbol");
            None
        }
    }
}

fn get_symbol_addr_from_symbol(
    section_headers: &[SectionHeader],
    symbol: &elf::symbol::Symbol,
) -> Option<usize> {
    let Some(section_header) = section_headers.get(symbol.st_shndx as usize) else {
        warn!("Failed to find section header for symbol");
        return None;
    };

    let Ok(addr) =
        usize::try_from(symbol.st_value - section_header.sh_addr + section_header.sh_offset)
    else {
        warn!("Failed to calculate address for symbol");
        return None;
    };

    Some(addr)
}

#[instrument(skip_all)]
fn find_symbols_in_symtab(elf: &mut ElfStream<AnyEndian, File>) -> Option<SymbolAddresses> {
    let section_headers = elf.section_headers().to_owned();

    let (symbol_table, string_table) = match elf.symbol_table() {
        Ok(Some(tables)) => tables,
        Ok(None) => {
            trace!("No SHT_SYMTAB section in executable file");
            return None;
        }
        Err(err) => {
            warn!(?err, "Failed to find SHT_SYMTAB section in executable file");
            return None;
        }
    };

    let mut ssl_ctrl = None;
    let mut ssl_free = None;
    let mut ssl_read = None;
    let mut ssl_read_ex = None;
    let mut ssl_write = None;
    let mut ssl_write_ex = None;
    let mut rustls_exists = false;
    let mut ring_exists = false;
    let mut evp_aead_ctx_init_with_direction = None;
    let mut evp_aead_ctx_seal = None;
    let mut evp_aead_ctx_open = None;
    let mut aes_hw_set_encrypt_key = None;
    #[cfg(target_arch = "x86_64")]
    let mut aesni_gcm_encrypt = None;
    #[cfg(target_arch = "x86_64")]
    let mut aesni_gcm_decrypt = None;
    #[cfg(target_arch = "aarch64")]
    let mut aes_gcm_enc_kernel = None;
    #[cfg(target_arch = "aarch64")]
    let mut aes_gcm_dec_kernel = None;
    let mut aes_hw_ctr32_encrypt_blocks = None;

    for sym in symbol_table {
        if sym.st_name == 0 {
            continue;
        }

        let Ok(name) = string_table.get(sym.st_name.try_into().unwrap()) else {
            continue;
        };

        match name {
            "SSL_ctrl" => ssl_ctrl = get_symbol_addr_from_symbol(&section_headers, &sym),
            "SSL_free" => ssl_free = get_symbol_addr_from_symbol(&section_headers, &sym),
            "SSL_read" => ssl_read = get_symbol_addr_from_symbol(&section_headers, &sym),
            "SSL_read_ex" => ssl_read_ex = get_symbol_addr_from_symbol(&section_headers, &sym),
            "SSL_write" => ssl_write = get_symbol_addr_from_symbol(&section_headers, &sym),
            "SSL_write_ex" => ssl_write_ex = get_symbol_addr_from_symbol(&section_headers, &sym),
            name => {
                if !rustls_exists && name.starts_with("_ZN6rustls6client") {
                    trace!("Found rustls symbols");
                    rustls_exists = true;
                } else if !ring_exists && name.starts_with("_ZN4ring4aead") {
                    trace!("Found ring symbols");
                    ring_exists = true;
                } else if name.ends_with("EVP_AEAD_CTX_init_with_direction") {
                    trace!("Found symbol EVP_AEAD_CTX_init_with_direction");
                    evp_aead_ctx_init_with_direction =
                        get_symbol_addr_from_symbol(&section_headers, &sym);
                } else if name.ends_with("EVP_AEAD_CTX_seal") {
                    trace!("Found symbol EVP_AEAD_CTX_seal");
                    evp_aead_ctx_seal = get_symbol_addr_from_symbol(&section_headers, &sym);
                } else if name.ends_with("EVP_AEAD_CTX_open") {
                    trace!("Found symbol EVP_AEAD_CTX_open");
                    evp_aead_ctx_open = get_symbol_addr_from_symbol(&section_headers, &sym);
                } else if name.ends_with("aes_hw_set_encrypt_key") {
                    trace!("Found symbol aes_hw_set_encrypt_key");
                    aes_hw_set_encrypt_key = get_symbol_addr_from_symbol(&section_headers, &sym);
                } else if name.ends_with("aes_hw_ctr32_encrypt_blocks") {
                    trace!("Found symbol aes_hw_ctr32_encrypt_blocks");
                    aes_hw_ctr32_encrypt_blocks =
                        get_symbol_addr_from_symbol(&section_headers, &sym);
                } else {
                    #[cfg(target_arch = "x86_64")]
                    if name.ends_with("aesni_gcm_encrypt") {
                        trace!("Found symbol aesni_gcm_encrypt");
                        aesni_gcm_encrypt = get_symbol_addr_from_symbol(&section_headers, &sym);
                    } else if name.ends_with("aesni_gcm_decrypt") {
                        trace!("Found symbol aesni_gcm_decrypt");
                        aesni_gcm_decrypt = get_symbol_addr_from_symbol(&section_headers, &sym);
                    } else {
                        continue;
                    }

                    #[cfg(target_arch = "aarch64")]
                    if name.ends_with("aes_gcm_enc_kernel") {
                        trace!("Found symbol aes_gcm_enc_kernel");
                        aes_gcm_enc_kernel = get_symbol_addr_from_symbol(&section_headers, &sym);
                    } else if name.ends_with("aes_gcm_dec_kernel") {
                        trace!("Found symbol aes_gcm_dec_kernel");
                        aes_gcm_dec_kernel = get_symbol_addr_from_symbol(&section_headers, &sym);
                    } else {
                        continue;
                    }
                }
            }
        }

        if ssl_ctrl.is_some()
            && ssl_free.is_some()
            && ssl_read.is_some()
            && ssl_read_ex.is_some()
            && ssl_write.is_some()
            && ssl_write_ex.is_some()
        {
            return Some(SymbolAddresses::LibSSL(LibSSLAddresses {
                ssl_ctrl: ssl_ctrl.unwrap(),
                ssl_free: ssl_free.unwrap(),
                ssl_read,
                ssl_read_ex,
                ssl_write,
                ssl_write_ex,
            }));
        }

        if let (
            true,
            Some(evp_aead_ctx_init_with_direction),
            Some(evp_aead_ctx_seal),
            Some(evp_aead_ctx_open),
        ) = (
            rustls_exists,
            evp_aead_ctx_init_with_direction,
            evp_aead_ctx_seal,
            evp_aead_ctx_open,
        ) {
            return Some(SymbolAddresses::Rustls(RustlsAddresses {
                evp_aead_ctx_init_with_direction,
                evp_aead_ctx_seal,
                evp_aead_ctx_open,
            }));
        }

        #[cfg(target_arch = "x86_64")]
        if let (
            true,
            Some(aes_hw_set_encrypt_key),
            Some(aesni_gcm_encrypt),
            Some(aesni_gcm_decrypt),
            Some(aes_hw_ctr32_encrypt_blocks),
        ) = (
            ring_exists,
            aes_hw_set_encrypt_key,
            aesni_gcm_encrypt,
            aesni_gcm_decrypt,
            aes_hw_ctr32_encrypt_blocks,
        ) {
            return Some(SymbolAddresses::Ring(RingAddresses {
                aes_hw_set_encrypt_key,
                aesni_gcm_encrypt,
                aesni_gcm_decrypt,
                aes_hw_ctr32_encrypt_blocks,
            }));
        }

        #[cfg(target_arch = "aarch64")]
        if let (
            true,
            Some(aes_hw_set_encrypt_key),
            Some(aes_gcm_enc_kernel),
            Some(aes_gcm_dec_kernel),
            Some(aes_hw_ctr32_encrypt_blocks),
        ) = (
            ring_exists,
            aes_hw_set_encrypt_key,
            aes_gcm_enc_kernel,
            aes_gcm_dec_kernel,
            aes_hw_ctr32_encrypt_blocks,
        ) {
            return Some(SymbolAddresses::Ring(RingAddresses {
                aes_hw_set_encrypt_key,
                aes_gcm_enc_kernel,
                aes_gcm_dec_kernel,
                aes_hw_ctr32_encrypt_blocks,
            }));
        }
    }

    if let (Some(ssl_ctrl), Some(ssl_free), true, true) = (
        ssl_ctrl,
        ssl_free,
        (ssl_read.is_some() || ssl_read_ex.is_some()),
        (ssl_write.is_some() || ssl_write_ex.is_some()),
    ) {
        return Some(SymbolAddresses::LibSSL(LibSSLAddresses {
            ssl_ctrl,
            ssl_free,
            ssl_read,
            ssl_read_ex,
            ssl_write,
            ssl_write_ex,
        }));
    }

    None
}

fn get_text_section_header(elf: &mut ElfStream<AnyEndian, File>) -> Option<SectionHeader> {
    const TEXT_SECTION_NAME: &str = ".text";

    match elf.section_header_by_name(TEXT_SECTION_NAME) {
        Ok(Some(text_section_header)) => Some(text_section_header.to_owned()),
        Ok(None) => {
            debug!("{TEXT_SECTION_NAME} section header does not exist");
            None
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to find {TEXT_SECTION_NAME} section in executable file"
            );
            None
        }
    }
}

#[instrument(skip_all)]
fn find_go_version(elf: &mut ElfStream<AnyEndian, File>) -> Option<GoVersion> {
    const GO_BUILDINFO_SECTION_NAME: &str = ".go.buildinfo";
    const GO_BUILDINFO_MAGIC: [u8; 14] = *b"\xff Go buildinf:";
    static GO_VERSION_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^go(\d+)\.(\d+)").unwrap());

    let go_buildinfo_section_header = match elf.section_header_by_name(GO_BUILDINFO_SECTION_NAME) {
        Ok(Some(go_buildinfo_section_header)) => go_buildinfo_section_header.to_owned(),
        Ok(None) => {
            debug!("{GO_BUILDINFO_SECTION_NAME} section header does not exist");
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to find {GO_BUILDINFO_SECTION_NAME} section in executable file"
            );
            return None;
        }
    };

    let go_buildinfo_section_data = match elf.section_data(&go_buildinfo_section_header) {
        Ok((data, None)) => data,
        Ok((_, Some(compression))) => {
            warn!(
                "{GO_BUILDINFO_SECTION_NAME} section data is compressed with an unknown algorithm: {compression:#?}"
            );
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to get {GO_BUILDINFO_SECTION_NAME} section data in executable file"
            );
            return None;
        }
    };

    let magic = &go_buildinfo_section_data[..GO_BUILDINFO_MAGIC.len()];
    if magic != GO_BUILDINFO_MAGIC {
        warn!("Incorrect Go buildinfo magic {magic:x?}, expected {GO_BUILDINFO_MAGIC:x?}");
        return None;
    }

    let ver_len = go_buildinfo_section_data[0x20] as usize;
    if ver_len >= 0x80 {
        warn!(
            ver_len = format!("0x{ver_len:x}"),
            "Invalid Go buildinfo version length"
        );
        return None;
    }

    let ver_bytes = &go_buildinfo_section_data[0x21..0x21 + ver_len];
    let ver_string = match std::str::from_utf8(ver_bytes) {
        Ok(ver_string) => ver_string,
        Err(err) => {
            warn!(
                ?err,
                ver_bytes = format!("{ver_bytes:x?}"),
                "Go version string is not valid UTF-8"
            );
            return None;
        }
    };

    match GO_VERSION_REGEX.captures(ver_string) {
        Some(captures) => {
            let Ok(major) = captures[1].parse::<u16>() else {
                warn!("Invalid Go major version {}", &captures[1]);
                return None;
            };

            let Ok(minor) = captures[2].parse::<u16>() else {
                warn!("Invalid Go minor version {}", &captures[2]);
                return None;
            };

            Some(GoVersion { major, minor })
        }
        None => None,
    }
}

#[instrument(skip_all)]
fn find_symbols_in_gopclntab(elf: &mut ElfStream<AnyEndian, File>) -> Option<GoTLSAddresses> {
    const GOPCLNTAB_SECTION_NAME: &str = ".gopclntab";

    let text_section_header = get_text_section_header(elf)?;

    let endianness = elf.ehdr.endianness;
    let class = elf.ehdr.class;

    let gopclntab_section_header = match elf.section_header_by_name(GOPCLNTAB_SECTION_NAME) {
        Ok(Some(gopclntab_section_header)) => gopclntab_section_header.to_owned(),
        Ok(None) => {
            debug!("{GOPCLNTAB_SECTION_NAME} section header does not exist");
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to find {GOPCLNTAB_SECTION_NAME} section in executable file"
            );
            return None;
        }
    };

    let gopclntab_section_data = match elf.section_data(&gopclntab_section_header) {
        Ok((data, None)) => data,
        Ok((_, Some(compression))) => {
            warn!(
                "{GOPCLNTAB_SECTION_NAME} section data is compressed with an unknown algorithm: {compression:#?}"
            );
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to get {GOPCLNTAB_SECTION_NAME} section data in executable file"
            );
            return None;
        }
    };

    let gopclntab = match GoPCLineTable::new(endianness, class, gopclntab_section_data) {
        Ok(gopclntab) => gopclntab,
        Err(elf::ParseError::BadMagic([0xF0, 0xFF, 0xFF, 0xFF])) => {
            debug!("Skipping executable compiled with Go < 1.20");
            return None;
        }
        Err(elf::ParseError::BadMagic([0xFA, 0xFF, 0xFF, 0xFF])) => {
            debug!("Skipping executable compiled with Go < 1.18");
            return None;
        }
        Err(elf::ParseError::BadMagic([0xFB, 0xFF, 0xFF, 0xFF])) => {
            debug!("Skipping executable compiled with Go < 1.16");
            return None;
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to parse {GOPCLNTAB_SECTION_NAME} section in executable file"
            );
            return None;
        }
    };

    match gopclntab.find_go_tls_symbols() {
        Ok(Some(ranges)) => {
            let sh_offset = usize::try_from(text_section_header.sh_offset)
                .expect("text section header offset should fit in usize");

            let handshake_context = GoSymbolAddress {
                entry: ranges.go_tls_handshake_context.start + sh_offset,
                exits: vec![],
            };

            let close = GoSymbolAddress {
                entry: ranges.go_tls_close.start + sh_offset,
                exits: vec![],
            };

            let read = match find_ret_isns_in_symbol(elf, &ranges.go_tls_read) {
                Some(ret_addrs) => GoSymbolAddress {
                    entry: ranges.go_tls_read.start + sh_offset,
                    exits: ret_addrs.iter().map(|exit| exit + sh_offset).collect(),
                },
                None => return None,
            };

            let write = match find_ret_isns_in_symbol(elf, &ranges.go_tls_write) {
                Some(ret_addrs) => GoSymbolAddress {
                    entry: ranges.go_tls_write.start + sh_offset,
                    exits: ret_addrs.iter().map(|exit| exit + sh_offset).collect(),
                },
                None => return None,
            };

            let go_version = find_go_version(elf)?;

            if go_version.major != 1 || go_version.minor < 21 {
                info!(
                    "Ignoring Go executable with unsupported version {}.{}",
                    go_version.major, go_version.minor
                );
                return None;
            }

            Some(GoTLSAddresses {
                go_version,
                handshake_context,
                close,
                read,
                write,
            })
        }
        Ok(None) => {
            debug!("Symbols not found");
            None
        }
        Err(err) => {
            warn!(
                ?err,
                "Failed to search for Go TLS symbols in executable file"
            );
            None
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn find_ret_isns_in_x86_64_bytecode(bytecode: &[u8], addr_start: usize) -> Option<Vec<usize>> {
    use std::{os::raw::c_char, ptr};

    use llvm_sys::{
        disassembler::{LLVMCreateDisasm, LLVMDisasmContextRef, LLVMDisasmInstruction},
        target::{
            LLVMInitializeX86AsmParser, LLVMInitializeX86AsmPrinter, LLVMInitializeX86Disassembler,
            LLVMInitializeX86Target, LLVMInitializeX86TargetInfo, LLVMInitializeX86TargetMC,
        },
    };

    struct SyncLLVMDisasmContextRef(LLVMDisasmContextRef);
    unsafe impl Send for SyncLLVMDisasmContextRef {}
    unsafe impl Sync for SyncLLVMDisasmContextRef {}

    const RETN_IMM: u8 = 0xc2;
    const RETN: u8 = 0xc3;
    const RETF_IMM: u8 = 0xca;
    const RETF: u8 = 0xcb;

    static LLVM_DISASM: LazyLock<SyncLLVMDisasmContextRef> = LazyLock::new(|| unsafe {
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmPrinter();
        LLVMInitializeX86AsmParser();
        LLVMInitializeX86Disassembler();
        SyncLLVMDisasmContextRef(LLVMCreateDisasm(
            c"x86_64-pc-linux".as_ptr().cast::<c_char>(),
            ptr::null_mut(),
            0,
            None,
            None,
        ))
    });

    let mut pc = 0;
    let mut buf = [0i8; 32];

    let mut ret_addrs = vec![];

    loop {
        let next_insts = &bytecode[pc..];

        let inst_size = unsafe {
            LLVMDisasmInstruction(
                LLVM_DISASM.0,
                // LLVMDisasmInstruction doesn't mutate the following 'Bytes' param, but it also doesn't mark it as const, so we have to mark it as a *mut u8 to prevent copy overhead
                next_insts.as_ptr().cast_mut(),
                next_insts.len().try_into().unwrap(),
                pc.try_into().unwrap(),
                buf.as_mut_ptr().cast::<c_char>(),
                buf.len(),
            )
        };

        if inst_size == 0 {
            break;
        }

        if matches!(next_insts[0], RETN_IMM | RETN | RETF_IMM | RETF) {
            ret_addrs.push(pc + addr_start);
        }

        pc += inst_size;
    }

    if ret_addrs.is_empty() {
        warn!("No return instructions found");
        return None;
    }

    Some(ret_addrs)
}

#[cfg(target_arch = "aarch64")]
fn find_ret_isns_in_aarch64_bytecode(bytecode: &[u8], addr_start: usize) -> Option<Vec<usize>> {
    let mut pc = 0;
    let mut ret_addrs = vec![];

    let bytecode = bytecode as *const [u8];

    let bytecode_u32: &[u32] = unsafe {
        #[allow(clippy::cast_ptr_alignment)]
        &*std::ptr::slice_from_raw_parts::<u32>(bytecode.cast::<u32>(), bytecode.len() / 4)
    };

    for opcode in bytecode_u32 {
        // https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions/RET--Return-from-subroutine-
        // Return address is in a register specified in bits 9:5, mask them out
        const RET_REG_MASK: u32 = 0xffff_fc1f;
        const RET_OPCODE: u32 = 0xd65f_0000;

        if (opcode & RET_REG_MASK) == RET_OPCODE {
            ret_addrs.push(pc + addr_start);
        }

        pc += 4;
    }

    if ret_addrs.is_empty() {
        warn!("No return instructions found");
        return None;
    }

    Some(ret_addrs)
}

#[instrument(skip(elf))]
fn find_ret_isns_in_symbol(
    elf: &mut ElfStream<AnyEndian, File>,
    addr: &Range<usize>,
) -> Option<Vec<usize>> {
    let Some(text_section_header) = get_text_section_header(elf) else {
        warn!(".text section header not found");
        return None;
    };

    let text_section_data = match elf.section_data(&text_section_header) {
        Ok((data, None)) => data,
        Ok((_, Some(compression))) => {
            warn!(".text section data is compressed with an unknown algorithm: {compression:#?}");
            return None;
        }
        Err(err) => {
            warn!(?err, "Failed to get .text section data in executable file");
            return None;
        }
    };

    let bytecode: &[u8] = &text_section_data[addr.start..addr.end];

    #[cfg(target_arch = "x86_64")]
    return find_ret_isns_in_x86_64_bytecode(bytecode, addr.start);

    #[cfg(target_arch = "aarch64")]
    return find_ret_isns_in_aarch64_bytecode(bytecode, addr.start);
}
