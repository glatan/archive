include!("src/compress/brotli/dict_index_build.rs");

fn main() {
    println!("cargo:rerun-if-changed=src/compress/brotli/dictionary.bin");
    println!("cargo:rerun-if-changed=src/compress/brotli/dict_index_build.rs");
    let dictionary =
        std::fs::read("src/compress/brotli/dictionary.bin").expect("brotli dictionary.bin");
    let built = build_dict_index(&dictionary);
    let mut bytes = Vec::new();
    for word in built.head.iter().chain(&built.next).chain(&built.entry) {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let out = std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR"))
        .join("brotli_dict_index.bin");
    std::fs::write(&out, bytes).expect("write brotli dict index");
    println!("cargo:rustc-env=BROTLI_DICT_INDEX={}", out.display());
}
