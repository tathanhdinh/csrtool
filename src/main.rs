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

use capstone::Capstone;
use capstone::CsArch;
use capstone::CsMode;
use capstone::instruction::Instructions;

fn disassemble_buffer(arch: CsArch, mode: CsMode, buffer: &[u8], base_address: usize, verbose: bool) {
    let cs = Capstone::new(arch, mode)
        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

    let insns = cs.disasm(&buffer, base_address as u64, 0)
        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

    let examined_bytes = insns.iter().fold(0usize, |acc, ins| acc + ins.size as usize);

    display_instructions(&insns, buffer, verbose);

    println!("(buffer has {} bytes, stop disassembling after {} bytes, get {} instructions)", buffer.len(), examined_bytes, insns.len());

    // use prettytable::Table;
    // use prettytable::format;
    // let mut table = Table::new();
    // table.set_format(*format::consts::FORMAT_CLEAN);

    // for ins in insns.iter() {
    //     // println!("{}", ins);
    //     let mnemonic = ins.mnemonic().unwrap_or("");
    //     let op = ins.op_str().unwrap_or("");
    //     let mnemonic_op_str = format!("{} {}", mnemonic, op);
    //     let addr_str = format!("{:#x}", ins.address);

    //     table.add_row(row![addr_str, mnemonic_op_str]);
    //     // println!("{:<#10x}  {} {}", ins.address, mnemonic, op);
    // }

    // table.printstd();
}

fn opcode_as_string(buffer: &[u8]) -> String {
    let mut opcode = String::new();

    for i in buffer {
        // opcode.extend(format!("{:02x} ", i).chars());
        opcode.push_str(format!("{:02x} ", i).as_str());
    }
    opcode.pop();
    opcode
}

fn display_instructions(insns: &Instructions, buffer: &[u8], verbose: bool) {
    use prettytable::Table;
    use prettytable::format;
    let mut table = Table::new();
    // table.set_format(*format::consts::FORMAT_CLEAN);
    let table_format = format::FormatBuilder::new()
        .padding(0, 3)
        .build();
    table.set_format(table_format);

    let mut ins_offset = 0usize;

    for ins in insns.iter() {
        // println!("{}", ins);
        let mnemonic = ins.mnemonic().unwrap_or("");
        let op = ins.op_str().unwrap_or("");
        let mnemonic_op_str = format!("{} {}", mnemonic, op);
        let addr_str = format!("{:#x}", ins.address);

        if verbose {
            let ins_size = ins.size as usize;
            let opcode_str = opcode_as_string(&buffer[ins_offset..ins_offset + ins_size]);
            ins_offset += ins_size;

            table.add_row(row![addr_str, opcode_str, mnemonic_op_str]);
        } else {
            table.add_row(row![addr_str, mnemonic_op_str]);
        }

        // println!("{:<#10x}  {} {}", ins.address, mnemonic, op);
    }

    table.printstd();
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
             .required(true))
        .arg(clap::Arg::with_name("length")
             .short("l")
             .long("length")
             .takes_value(true)
             .help("Number of disassemlet nopSledding = [| for _ in 0..7 -> (byte 0x90) |]bled bytes (or disassembling until EOF)")
             .required(false))
        .arg(clap::Arg::with_name("base address")
             .long("base")
             .help("Base address of disassembled instructions")
             .takes_value(true)
             .default_value(default_base_address.as_str())
             .required(false))
        .arg(clap::Arg::with_name("smc")
             .long("smc")
             .help("Enable overlapped and self-modifying code analysis")
             .required(false))
        .arg(clap::Arg::with_name("file")
             .short("f")
             .long("file")
             .help("Disassembled input file")
             .takes_value(true)
             .required(true)
             .conflicts_with("string"))
        .arg(clap::Arg::with_name("string")
             .short("s")
             .long("string")
             .help("Disassembled input string (accept all hex separators, even mixed)")
             .takes_value(true).required(true)
             .conflicts_with_all(&["file", "file offset"]))
        .arg(clap::Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .help("Display instruction detail")
             .takes_value(false)
             .required(false))
        .get_matches();

    // let mode = matches.value_of("mode").unwrap_or_default();
    // match matches.value_of("file") {
    //     Some(file) => {
    //     },
    //     _ => {
    //         println!("unknown input file");
    //     }
    // }

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
                            let base_address = value_t!(matches.value_of("base address"), usize)
                                .unwrap_or_else(|e| e.exit());

                            let is_verbose = matches.is_present("verbose");

                            if matches.is_present("file") {
                                let input_filename = value_t!(matches.value_of("file"), String).unwrap_or_else(|e| e.exit());

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

                                        disassemble_buffer(capstone::CsArch::ARCH_X86, capstone::CsMode::MODE_32, &buffer, base_address, is_verbose);

                                        // let cs = capstone::Capstone::new(capstone::CsArch::ARCH_X86, capstone::CsMode::MODE_32)
                                        //     .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                        // let insns = cs.disasm(&buffer, base_address as u64, 0)
                                        //     .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                        // let mut table = prettytable::Table::new();
                                        // table.set_format(*prettytable::format::consts::FORMAT_CLEAN);

                                        // for ins in insns.iter() {
                                        //     // println!("{}", ins);
                                        //     let mnemonic = ins.mnemonic().unwrap_or("");
                                        //     let op = ins.op_str().unwrap_or("");
                                        //     let mnemonic_op_str = format!("{} {}", mnemonic, op);
                                        //     let addr_str = format!("{:#x}", ins.address);

                                        //     table.add_row(row![addr_str, mnemonic_op_str]);
                                        //     // println!("{:<#10x}  {} {}", ins.address, mnemonic, op);
                                        // }

                                        // table.printstd();

                                    } else {
                                        println!("offset is too large")
                                    }
                                } else {
                                    println!("{} is not a valid file", input_filename);
                                }
                            } else {
                                // let hex_string_values = Vec::new();

                                let input_string = value_t!(matches.value_of("string"), String).unwrap_or_else(|e| e.exit());
                                let all_strings_space_sep = input_string.split(" ").collect::<Vec<&str>>();

                                let mut all_strings_space_0x_sep = Vec::new();
                                for s in all_strings_space_sep {
                                    let strings_space_0x_sep = s.split("0x").collect::<Vec<&str>>();
                                    all_strings_space_0x_sep.extend_from_slice(strings_space_0x_sep.as_slice());
                                }

                                let mut all_strings_space_0x_c0x_sep = Vec::new();
                                for s in all_strings_space_0x_sep {
                                    let strings_space_0x_c0x_sep = s.split("\\x").collect::<Vec<&str>>();
                                    all_strings_space_0x_c0x_sep.extend_from_slice(strings_space_0x_c0x_sep.as_slice());
                                }

                                let mut all_strings_space_0x_c0x_comma_sep = Vec::new();
                                for s in all_strings_space_0x_c0x_sep {
                                    let strings_space_0x_c0x_comma_sep = s.split(":").collect::<Vec<&str>>();
                                    all_strings_space_0x_c0x_comma_sep.extend_from_slice(strings_space_0x_c0x_comma_sep.as_slice());
                                }

                                let mut all_strings_space_0x_c0x_comma_colon_sep = Vec::new();
                                for s in all_strings_space_0x_c0x_comma_sep {
                                    let strings_space_0x_c0x_comma_colon_sep = s.split(",").collect::<Vec<&str>>();
                                    all_strings_space_0x_c0x_comma_colon_sep.extend_from_slice(strings_space_0x_c0x_comma_colon_sep.as_slice());
                                }

                                let mut all_strings_all_sep = Vec::new();
                                for s in all_strings_space_0x_c0x_comma_colon_sep {
                                    let strings_all_sep = s.split(";").collect::<Vec<&str>>();
                                    all_strings_all_sep.extend_from_slice(strings_all_sep.as_slice());
                                }

                                let mut buffer = Vec::new();
                                for s in all_strings_all_sep {
                                    buffer.push(u8::from_str_radix(s, 0x10).unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); }));
                                }

                                disassemble_buffer(capstone::CsArch::ARCH_X86, capstone::CsMode::MODE_32, &buffer, base_address, is_verbose);
                            }
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
