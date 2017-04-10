#[macro_use] extern crate clap;

extern crate capstone;

arg_enum!{
        #[allow(non_camel_case_types)]
        enum AddressingModes {
            x16,
            x32,
            x64
        }
    }

arg_enum!{
    #[allow(non_camel_case_types)]
    enum Architectures {
        arm,
        aarch64,
        mips,
        powerpc,
        sparc,
        systemz,
        x86,
        xcore
    }
}

arg_enum!{
    #[allow(non_camel_case_types)]
    enum AssemblySyntax {
        intel,
        att
    }
}

fn main() {
    // let supported_modes = vec!["x16", "x32", "x64"];
    // let supported_archs = vec!["arm", "aarch64", "mips", "powerpc", "sparc", "systemz", "x86", "xcore"];

    let default_addressing_mode = AddressingModes::x32.to_string();
    let default_assembly_syntax = AssemblySyntax::intel.to_string();

    let matches = clap::App::new("csrtool")
        .version("0.1")
        .author("Ta Thanh Dinh <tathanhdinh@gmail.com>")
        .about("an improved cstool")
        .arg(clap::Arg::with_name("mode")
             .short("m")
             .long("mode")
             .help("Addressing mode")
             .possible_values(&AddressingModes::variants())
             .default_value(default_addressing_mode.as_str())
             .required(false))
        .arg(clap::Arg::with_name("arch")
             .long("arch")
             .help("CPU architecture")
             .required(true)
             .possible_values(&Architectures::variants())
             .default_value("x86")
             .required(false))
        .arg(clap::Arg::with_name("syntax")
             .long("syntax")
             .help("Assembly syntax")
             .possible_values(&AssemblySyntax::variants())
             .default_value(default_assembly_syntax.as_str())
             .required(false))
        .arg(clap::Arg::with_name("physical offset")
             .long("offset")
             .help("Start disassembling from a physical offset")
             .default_value("0")
             .required(false))
        .arg(clap::Arg::with_name("length")
             .short("l")
             .long("length")
             .help("Number of disassembled bytes (or disassembling until EOF)")
             .required(false))
        .arg(clap::Arg::with_name("smc")
             .long("smc")
             .help("Support self-modifying code")
             .required(false))
        .get_matches();

    // let mode = matches.value_of("mode").unwrap_or_default();
    let mode = value_t!(matches.value_of("mode"), AddressingModes).unwrap_or_else(|e| e.exit());
    let arch = value_t!(matches.value_of("arch"), Architectures).unwrap_or_else(|e| e.exit());
    // let disasm_syntax = val
}
