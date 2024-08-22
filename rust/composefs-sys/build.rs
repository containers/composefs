fn main() {
    #[cfg(not(feature = "dox"))]
    if let Err(s) = system_deps::Config::new().probe() {
        println!("cargo:warning={s}");
        std::process::exit(1);
    }
}
