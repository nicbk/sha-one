// Implemented pursuant to NIST FIPS 180-4
// available at https://doi.org/10.6028/NIST.FIPS.180-4
use {
    std::{
        num::Wrapping,
        cmp::max,
    }
};

// Unit tests for this implementation of the 
// SHA1 function
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum HashError {
    // Data to be hashed by SHA1 greater
    // than or equal to 2^64 bits in length
    DataTooLarge
}

// Encapsulate raw hash in a struct with
// convenience function to convert hash
// to hex string
pub struct Sha1 {
    hash: [u32; 5],
}

impl Sha1 {
    pub fn new(inp: &[u8]) -> Result<Sha1, HashError> {
        Ok(Sha1 {
            hash: sha1(inp)?
        })
    }

    pub fn to_string(&self) -> String {
        format!("{:08x}{:08x}{:08x}{:08x}{:08x}", 
                self.hash[0],
                self.hash[1],
                self.hash[2],
                self.hash[3],
                self.hash[4])
    }
}

// SHA1 function takes in a u8 slice that is
// less than 2^64 bits in length and returns
// a 160 bit hash composed of u32 bit parts
fn sha1(inp: &[u8]) -> Result<[u32; 5], HashError> {
    if inp.len() >= 2 << 61 {
        return Err(HashError::DataTooLarge);
    }

    // Initial hash values to be used.
    let mut hash: [Wrapping<u32>; 5] = [
        Wrapping(0x67452301),
        Wrapping(0xefcdab89),
        Wrapping(0x98badcfe),
        Wrapping(0x10325476),
        Wrapping(0xc3d2e1f0),
    ];

    let blocks = pad_data(inp);

    for i in 0..blocks.len() {
        block(&mut hash, &blocks[i]);
    }

    Ok([
       hash[0].0,
       hash[1].0,
       hash[2].0,
       hash[3].0,
       hash[4].0,
    ])
}

fn block(hash: &mut [Wrapping<u32>; 5], block: &[Wrapping<u32>; 16]) {
    // Message schedule used for the rounds
    let mut w = [Wrapping(0_u32); 80];

    let (mut a, mut b, mut c, mut d, mut e)
        = (
            hash[0],
            hash[1],
            hash[2],
            hash[3],
            hash[4]
          );

    // Iterate through each round
    for i in 0..80 {
        match i {
            0..=15  => w[i] = block[i],
            16..=79 =>
                // TODO: Directly execute 'rotate_left' on the w[i] expressions
                // if the feature is stabilized in Wrapping.
                w[i] = Wrapping((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).0
                .rotate_left(1)),
            _ => panic!("Error: in function 'block': round greater\
                    than 79 was provided to the message schedule"),
        }

        // TODO: Directly execute 'rotate_left' on 'a' if the feature is stabilized
        // in Wrapping.
        let t = Wrapping(a.0.rotate_left(5))
              + Wrapping(f(i as u8, b.0, c.0, d.0))
              + e
              + Wrapping(sha1_const(i as u8))
              + w[i];

        e = d;
        d = c;
        c = Wrapping(b.0.rotate_left(30));
        b = a;
        a = t;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
}

// Converts u8 slice into a vector of 512 bit 
// blocks, represented as u32 arrays with 
// length 16
fn pad_data(inp: &[u8]) -> Vec<[Wrapping<u32>; 16]> {
    let inp_len_bits = inp.len() * 8;
                     // Divide size of input data by
                     // size of a single block
                     //
                     // max function used because if length of
                     // input is zero, then there still needs to be
                     // one block
    let num_blocks = max(((inp_len_bits as f32 / 512_f32).ceil()
                     // If there is not enough space
                     // left in a block to insert a '1' bit
                     // and the 64 bit number representing
                     // the size of the input data,
                     // then add one more block.
                   + ((inp_len_bits % 512) as f32 / 448_f32).floor()) as usize, 1);

    let mut blocks = vec![[Wrapping(0_u32); 16]; num_blocks];

    let mut block_num = 0;
    let mut block_pos = 0;

    for (i, x) in inp.iter().enumerate() {
        // Current block
        block_num = (i as f32 / 64_f32).floor() as usize;
        // Current position in block
        block_pos = ((i % 64) as f32 / 4_f32).floor() as usize;

        // Big Endian implementation, fill up empty u32 elements
        // by ORing it with four u8 elements starting from
        // left to right.
        blocks[block_num][block_pos].0 |= (*x as u32) << 24 - (i % 4 * 8);
    }

    // Which u32 segment the '1' bit should occupy after
    // the last u8 input byte
    let next_input = inp.len() % 4;

    if next_input == 0 && inp.len() > 0 {
        if block_pos == 15 {
            block_pos = 0;
            block_num = 0;
        } else {
            block_pos += 1;
        }
    }

    // Set most significant bit (which is the bit neighboring
    // the last input byte) to '1'
    blocks[block_num][block_pos].0 |= 128_u32 << 24 - next_input * 8;

    // Fill end of last block with 64 bit number representing
    // size of input data in bits
    let blocks_len = blocks.len();
    blocks[blocks_len - 1][15].0 = inp_len_bits as u32;
    blocks[blocks_len - 1][14].0 = (inp_len_bits >> 32) as u32;

    blocks
}

// Logical function for scrambling data in each round
//
// Function used for internal implementation of SHA1,
// should panic if invalid round provided
fn f(round: u8, x: u32, y: u32, z: u32) -> u32 {
    match round {
                // Ch(x, y, z)
        00..=19 => (x & y) ^ (!x & z),
                // Parity(x, y, z)
        20..=39 => x ^ y ^ z,
                // Maj(x, y, z)
        40..=59 => (x & y) ^ (x & z) ^ (y & z),
                // Parity(x, y, z)
        60..=79 => x ^ y ^ z,
        _ => panic!("Error: in function 'f': round greater\
                than 79 was provided."),
    }
}

// Constants fed into each round of SHA1.
//
// Function used for internal implementation of SHA1,
// should panic if invalid round provided.
fn sha1_const(round: u8) -> u32 {
    match round {
        00..=19 => 0x5a827999,
        20..=39 => 0x6ed9eba1,
        40..=59 => 0x8f1bbcdc,
        60..=79 => 0xca62c1d6,
        _ => panic!("Error: in function 'sha1_const': round greater\
                than 79 was provided."),
    }
}
