pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = (sum & 0xffff) + (sum >> 16);
    }

    if let [byte] = chunks.remainder() {
        sum += (*byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_empty_input_is_all_ones() {
        assert_eq!(checksum(&[]), 0xffff);
    }

    #[test]
    fn computes_a_known_ipv4_header_checksum() {
        let header_without_checksum = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        assert_eq!(checksum(&header_without_checksum), 0xb861);
    }

    #[test]
    fn valid_header_including_its_checksum_reduces_to_zero() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        assert_eq!(checksum(&header), 0);
    }

    #[test]
    fn treats_an_odd_final_byte_as_the_high_byte_of_a_word() {
        assert_eq!(checksum(&[0x01, 0x02, 0x03]), 0xfbfd);
    }

    #[test]
    fn folds_end_around_carry() {
        assert_eq!(checksum(&[0xff, 0xff, 0x00, 0x01]), 0xfffe);
    }
}
