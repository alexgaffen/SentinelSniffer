fn main() {
    // This tells the Rust compiler exactly where to find Packet.lib
    // NOTE: If your npcap-sdk is NOT in C:\Libs\, change this path!
    println!("cargo:rustc-link-search=native=C:\\Libs\\npcap-sdk\\Lib\\x64");
}