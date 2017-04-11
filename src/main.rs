#[macro_use] extern crate clap;

extern crate capstone;

#[macro_use] extern crate prettytable;

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
    let default_architecture = Architectures::x86.to_string();
    let default_assembly_syntax = AssemblySyntax::intel.to_string();
    let default_base_address = 0usize.to_string();
    let default_file_offset = 0usize.to_string();

    let matches = clap::App::new("csrtool - an improved objdump (Ta Thanh Dinh <tathanhdinh@gmail.com>)")
        // .version("0.1")
        // .author("Ta Thanh Dinh <tathanhdinh@gmail.com>")
        // .about("an improved cstool")
        .arg(clap::Arg::with_name("mode")
             .short("m")
             .long("mode")
             .help("Addressing mode")
             .takes_value(true)
             .possible_values(&AddressingModes::variants())
             .default_value(default_addressing_mode.as_str())
             .required(false))
        .arg(clap::Arg::with_name("arch")
             .long("arch")
             .help("CPU architecture")
             .takes_value(true)
             .possible_values(&Architectures::variants())
             .default_value(default_architecture.as_str())
             .required(false))
        .arg(clap::Arg::with_name("syntax")
             .long("syntax")
             .help("Assembly syntax")
             .takes_value(true)
             .possible_values(&AssemblySyntax::variants())
             .default_value(default_assembly_syntax.as_str())
             .required(false))
        .arg(clap::Arg::with_name("file offset")
             .long("offset")
             .takes_value(true)
             .help("Start disassembling from a file offset")
             .default_value(default_file_offset.as_str())
             .required(false))
        .arg(clap::Arg::with_name("length")
             .short("l")
             .long("length")
             .takes_value(true)
             .help("Number of disassembled bytes (or disassembling until EOF)")
             .required(false))
        .arg(clap::Arg::with_name("base address")
             .long("base")
             .help("Base address of disassembled instructions")
             .takes_value(true)
             .default_value(default_base_address.as_str())
             .required(false))
        .arg(clap::Arg::with_name("smc")
             .long("smc")
             .help("Support self-modifying code")
             .required(false))
        .arg(clap::Arg::with_name("file")
             .short("f")
             .long("file")
             .help("Input file")
             .takes_value(true)
             .required(true))
        .get_matches();

    // let mode = matches.value_of("mode").unwrap_or_default();
    // match matches.value_of("file") {
    //     Some(file) => {
    //     },
    //     _ => {
    //         println!("unknown input file");
    //     }
    // }

    let input_filename = value_t!(matches.value_of("file"), String).unwrap_or_else(|e| e.exit());
    // let input_filename = matches.value_of("file").unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

    let mode = value_t!(matches.value_of("mode"), AddressingModes).unwrap_or_else(|e| e.exit());
    let arch = value_t!(matches.value_of("arch"), Architectures).unwrap_or_else(|e| e.exit());
    let disasm_syntax = value_t!(matches.value_of("syntax"), AssemblySyntax).unwrap_or_else(|e| e.exit());

    match mode {
        AddressingModes::x32 => {
            match arch {
                Architectures::x86 => {
                    match disasm_syntax {
                        AssemblySyntax::intel => {
                            let poff = value_t!(matches.value_of("file offset"), usize).unwrap_or_else(|e| e.exit());
                            // let file_metadata = std::fs::metadata(input_filename.as_str()).unwrap_or_else(|e| println!("{}", e));
                            let file_metadata = std::fs::metadata(input_filename.as_str())
                                .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                            if file_metadata.is_file() {
                                let file_length = file_metadata.len() as usize;

                                if poff < file_length {
                                    let mut input_file = std::fs::File::open(input_filename.as_str())
                                        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                    use std::io::Seek;
                                    input_file.seek(std::io::SeekFrom::Start(poff as u64))
                                        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                    // let nb_read = value_t!(matches.value_of("length"), usize).unwrap_or(0);
                                    let mut buffer: Vec<u8> =
                                        match value_t!(matches.value_of("length"), usize) {
                                            Ok(nb_to_read) => vec![0; nb_to_read],
                                            Err(_) => vec![0; file_length - poff],
                                        };

                                    // let mut buffer: Vec<u8> = vec![];
                                    use std::io::Read;
                                    let mut reader = std::io::BufReader::new(input_file);
                                    let nb_read = reader.read(buffer.as_mut_slice())
                                        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });
                                    buffer.truncate(nb_read);

                                    let base_address = value_t!(matches.value_of("base address"), usize)
                                        .unwrap_or_else(|e| e.exit());

                                    let cs = capstone::Capstone::new(capstone::CsArch::ARCH_X86, capstone::CsMode::MODE_32)
                                        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                    let insns = cs.disasm(&buffer, base_address as u64, 0)
                                        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                    let mut table = prettytable::Table::new();
                                    table.set_format(*prettytable::format::consts::FORMAT_CLEAN);

                                    for ins in insns.iter() {
                                        // println!("{}", ins);
                                        let mnemonic = ins.mnemonic().unwrap_or("");
                                        let op = ins.op_str().unwrap_or("");
                                        let mnemonic_op_str = format!("{} {}", mnemonic, op);
                                        let addr_str = format!("{:#x}", ins.address);

                                        table.add_row(row![addr_str, mnemonic_op_str]);
                                        // println!("{:<#10x}  {} {}", ins.address, mnemonic, op);
                                    }

                                    table.printstd();

                                    // match std::fs::File::open(input_filename.as_str()) {
                                    //     Ok(mut input_file) => {
                                    //         use std::io::Seek;
                                    //         input_file.seek(std::io::SeekFrom::Start(poff as u64)).unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });
                                    //     },
                                    //     Err(e) => {
                                    //         println!("{}", e);
                                    //     }
                                    // }

                                } else {
                                    println!("offset is too large")
                                }
                            } else {
                                println!("{} is not a valid file", input_filename);
                            }

                            // match std::fs::metadata(input_filename.as_str()) {
                            //     Ok(file_metadata) => {
                            //         if file_metadata.is_file() {
                            //             println!("{} is not a valid file", input_filename);
                            //         } else {
                            //             let file_length = file_metadata.len() as usize;

                            //             if poff < file_length {
                            //                 let mut input_file = std::fs::File::open(input_filename.as_str())
                            //                     .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                            //                 use std::io::Seek;
                            //                 input_file.seek(std::io::SeekFrom::Start(poff as u64))
                            //                     .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                            //                 let mut buffer: Vec<u8> = Vec::new();

                            //                 // match std::fs::File::open(input_filename.as_str()) {
                            //                 //     Ok(mut input_file) => {
                            //                 //         use std::io::Seek;
                            //                 //         input_file.seek(std::io::SeekFrom::Start(poff as u64)).unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });
                            //                 //     },
                            //                 //     Err(e) => {
                            //                 //         println!("{}", e);
                            //                 //     }
                            //                 // }

                            //             } else {
                            //                 println!("offset is too large")
                            //             }
                            //         }
                            //     },
                            //     Err(e) => {
                            //         println!("{}", e);
                            //     }
                            // }
                        },
                        asm_syntax @ _ => {
                            println!("assembly syntax {} is not supported yet", asm_syntax);
                        }
                    }
                },
                arch @ _ => {
                    println!("architecture {} is not supported yet", arch);
                }
            }
        },
        mode @ _ => {
            println!("mode {} is not supported yet", mode);
        }
    }
}
