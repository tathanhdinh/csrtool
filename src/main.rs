extern crate capstone;
extern crate clap;

fn main() {
    let matches = clap::App::new("csrtool")
        .version("0.1")
        .author("Ta Thanh Dinh <tathanhdinh@gmail.com>")
        .about("an improved cstool")
        .arg(clap::Arg::with_name("mode")
             .short("m")
             .long("mode")
             .help("Addressing mode")
             .required(true))
        .arg(clap::Arg::with_name("arch")
             // .long("arch")
             .help("CPU architecture")
             .required(true))
        .arg(clap::Arg::with_name("syntax")
             .help("Assembly syntax")
             .possible_values(&["intel", "att"])
             .default_value("intel").required(false))
        .get_matches();
}
