/// This function is to assist in no-alloc base64 encoding of 256 bits.
pub fn base64_encode_256_bits<'a>(input_byte_v: &[u8; 32], buffer: &'a mut [u8; 43]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 encoding of 512 bits.
pub fn base64_encode_512_bits<'a>(input_byte_v: &[u8; 64], buffer: &'a mut [u8; 86]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 decoding of 256 bits.
/// 256 bits is 43 base64 chars (rounded up), but 43 base64 chars is 258 bits,
/// so there has to be an extra byte in the buffer for base64 to decode into.
pub fn base64_decode_256_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 33],
) -> Result<&'a [u8; 32], &'static str> {
    if !input_str.is_ascii() {
        return Err("not ASCII");
    }
    if input_str.len() != 43 {
        return Err("expected 43 base64 chars");
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 256 bit value failed")?;
    // Ensure that the last byte is zero, otherwise there were more than 256 bits in the base64 string.
    if buffer[32] != 0 {
        return Err("does not parse as 256 bit value");
    }
    // Cut off the last byte, which we know is zero.
    let output_byte_v: &[u8; 32] = buffer[0..32].try_into().unwrap();
    Ok(output_byte_v)
}

/// This function is to assist in no-alloc base64 decoding of 512 bits.
/// 512 bits is 86 base64 chars (rounded up), but 86 base64 chars is 516 bits,
/// so there has to be an extra byte in the buffer for base64 to decode into.
/// Actually there has to be 2 extra bytes, because base64 crate seems to require it.
pub fn base64_decode_512_bits<'a>(
    input_str: &str,
    buffer: &'a mut [u8; 66],
) -> Result<&'a [u8; 64], &'static str> {
    if !input_str.is_ascii() {
        return Err("not ASCII");
    }
    if input_str.len() != 86 {
        return Err("expected 86 base64 chars");
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|e| {
            println!("base64 error: {}", e);
            "base64 decode of 512 bit value failed"
        })?;
    // Ensure that the last bytes are zero, otherwise there were more than 512 bits in the base64 string.
    if buffer[64] != 0 || buffer[65] != 0 {
        return Err("does not parse as 512 bit value");
    }
    // Cut off the last byte, which we know is zero.
    let output_byte_v: &[u8; 64] = buffer[0..64].try_into().unwrap();
    Ok(output_byte_v)
}
