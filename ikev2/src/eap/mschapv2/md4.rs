// Cloned from linux/crypto/md4.c
const BLOCK_LEN: usize = 64;
const DIGEST_LEN: usize = 16;

pub fn md4(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut state = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    let full_blocks = input.len() / BLOCK_LEN;
    for block in input[..full_blocks * BLOCK_LEN].chunks_exact(BLOCK_LEN) {
        let words = decode_block(block);
        transform(&mut state, &words);
    }

    let tail = &input[full_blocks * BLOCK_LEN..];
    let bit_len = (input.len() as u64) << 3;
    let mut block = [0u8; BLOCK_LEN];
    block[..tail.len()].copy_from_slice(tail);
    block[tail.len()] = 0x80;

    if tail.len() >= 56 {
        let words = decode_block(&block);
        transform(&mut state, &words);
        block = [0u8; BLOCK_LEN];
    }

    block[56..64].copy_from_slice(&bit_len.to_le_bytes());
    let words = decode_block(&block);
    transform(&mut state, &words);

    let mut out = [0u8; DIGEST_LEN];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn decode_block(block: &[u8]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

fn transform(state: &mut [u32; 4], block: &[u32; 16]) {
    let [mut a, mut b, mut c, mut d] = *state;

    round_1(&mut a, b, c, d, block[0], 3);
    round_1(&mut d, a, b, c, block[1], 7);
    round_1(&mut c, d, a, b, block[2], 11);
    round_1(&mut b, c, d, a, block[3], 19);
    round_1(&mut a, b, c, d, block[4], 3);
    round_1(&mut d, a, b, c, block[5], 7);
    round_1(&mut c, d, a, b, block[6], 11);
    round_1(&mut b, c, d, a, block[7], 19);
    round_1(&mut a, b, c, d, block[8], 3);
    round_1(&mut d, a, b, c, block[9], 7);
    round_1(&mut c, d, a, b, block[10], 11);
    round_1(&mut b, c, d, a, block[11], 19);
    round_1(&mut a, b, c, d, block[12], 3);
    round_1(&mut d, a, b, c, block[13], 7);
    round_1(&mut c, d, a, b, block[14], 11);
    round_1(&mut b, c, d, a, block[15], 19);

    round_2(&mut a, b, c, d, block[0], 3);
    round_2(&mut d, a, b, c, block[4], 5);
    round_2(&mut c, d, a, b, block[8], 9);
    round_2(&mut b, c, d, a, block[12], 13);
    round_2(&mut a, b, c, d, block[1], 3);
    round_2(&mut d, a, b, c, block[5], 5);
    round_2(&mut c, d, a, b, block[9], 9);
    round_2(&mut b, c, d, a, block[13], 13);
    round_2(&mut a, b, c, d, block[2], 3);
    round_2(&mut d, a, b, c, block[6], 5);
    round_2(&mut c, d, a, b, block[10], 9);
    round_2(&mut b, c, d, a, block[14], 13);
    round_2(&mut a, b, c, d, block[3], 3);
    round_2(&mut d, a, b, c, block[7], 5);
    round_2(&mut c, d, a, b, block[11], 9);
    round_2(&mut b, c, d, a, block[15], 13);

    round_3(&mut a, b, c, d, block[0], 3);
    round_3(&mut d, a, b, c, block[8], 9);
    round_3(&mut c, d, a, b, block[4], 11);
    round_3(&mut b, c, d, a, block[12], 15);
    round_3(&mut a, b, c, d, block[2], 3);
    round_3(&mut d, a, b, c, block[10], 9);
    round_3(&mut c, d, a, b, block[6], 11);
    round_3(&mut b, c, d, a, block[14], 15);
    round_3(&mut a, b, c, d, block[1], 3);
    round_3(&mut d, a, b, c, block[9], 9);
    round_3(&mut c, d, a, b, block[5], 11);
    round_3(&mut b, c, d, a, block[13], 15);
    round_3(&mut a, b, c, d, block[3], 3);
    round_3(&mut d, a, b, c, block[11], 9);
    round_3(&mut c, d, a, b, block[7], 11);
    round_3(&mut b, c, d, a, block[15], 15);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline]
fn round_1(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32) {
    *a = a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s);
}

#[inline]
fn round_2(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32) {
    *a = a.wrapping_add(g(b, c, d)).wrapping_add(k).wrapping_add(0x5a82_7999).rotate_left(s);
}

#[inline]
fn round_3(a: &mut u32, b: u32, c: u32, d: u32, k: u32, s: u32) {
    *a = a.wrapping_add(h(b, c, d)).wrapping_add(k).wrapping_add(0x6ed9_eba1).rotate_left(s);
}
