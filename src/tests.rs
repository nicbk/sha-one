use crate::*;

#[test]
fn pad_data_no_input() {
    let blocks = pad_data(&[]);
    assert_eq!(blocks, [[Wrapping(2147483648)
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0) 
               , Wrapping(0)]]);
}

#[test]
fn pad_data_one_block() {
    let blocks = pad_data(b"Hello, world! The world is here.");
    assert_eq!(blocks, [[Wrapping(1214606444)
               , Wrapping(1865162871)
               , Wrapping(1869769828)
               , Wrapping(555766888)
               , Wrapping(1696626543)
               , Wrapping(1919706144)
               , Wrapping(1769152616)
               , Wrapping(1701995822)
               , Wrapping(2147483648)
               , Wrapping(0)
               , Wrapping(0)
               , Wrapping(0)
               , Wrapping(0)
               , Wrapping(0)
               , Wrapping(0)
               , Wrapping(256)]]);
}

#[test]
fn sha1_large_file() {
    use std::fs::read;

    let gnu_make_source = read("make-4.2.1.tar.gz")
        .expect("Unable to open GNU Make tarball!");

    let hash_string = Sha1::new(&gnu_make_source[..])
        .unwrap()
        .to_string();

    assert_eq!(hash_string, "9cb7f45f6e32c977164ba790e626c359d3a24fee");
}
