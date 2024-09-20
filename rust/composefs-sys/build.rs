fn main() {
    #[cfg(not(docsrs))]
    if let Err(s) = system_deps::Config::new().probe() {
        println!("cargo:warning={s}");
        std::process::exit(1);
    }
}
