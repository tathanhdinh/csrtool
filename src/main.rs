#[macro_use] extern crate clap;
#[macro_use] extern crate prettytable;

extern crate num;
extern crate capstone;
extern crate xmas_elf;


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

    println!("({} instructions, {}/{} bytes disassembled)", insns.len(), examined_bytes, buffer.len());
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

use clap::Error;
fn parse_value_from_string<T: std::str::FromStr + num::traits::Num>(input: &str) -> T {
    let report_error = |_| Error::value_validation_auto(format!("The argument '{}' isn't a valid value",
                                                                input)).exit();

    if input.len() > 2 {
        // let base_address_str_prefix = base_address_str[..2];
        let (input_prefix, input_value) = input.split_at(2);

        match input_prefix {
            "0x" => { T::from_str_radix(input_value, 0x10)
                      .unwrap_or_else(report_error) },
            "0o" => { T::from_str_radix(input_value, 0x8)
                      .unwrap_or_else(report_error) },
            "0b" => { T::from_str_radix(input_value, 0x2)
                      .unwrap_or_else(report_error) }
            // _ => { input.parse::<T>()
            //        .unwrap_or_else(report_error) }
            _ => { T::from_str_radix(input, 0xa).unwrap_or_else(report_error) }
        }
    } else {
        // input.parse::<T>().unwrap_or_else(report_error)
        T::from_str_radix(input, 0xa).unwrap_or_else(report_error)
    }
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
    let default_addressing_mode = AddressingModes::x32.to_string();
    let default_architecture = Architectures::x86.to_string();
    let default_assembly_syntax = AssemblySyntax::intel.to_string();
    // let default_base_address = 0usize.to_string();
    // let default_file_offset = 0usize.to_string();

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
            //  .default_value(default_file_offset.as_str())
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
            //  .default_value(default_base_address.as_str())
             .required(false))
        .arg(clap::Arg::with_name("smc")
             .long("smc")
             .help("Enables overlapped and self-modifying code analysis")
             .required(false))
        .arg(clap::Arg::with_name("file")
             .short("f")
             .long("file")
             .help("Disassembled input file")
             .takes_value(true)
             .required(false)
             .conflicts_with("string"))
        .arg(clap::Arg::with_name("string")
             .short("s")
             .long("string")
             .help("Disassembled input string (accept all hex separators, even mixed)")
             .takes_value(true)
             .conflicts_with_all(&["file", "file offset"])
             .required(true))
        .arg(clap::Arg::with_name("verbose")
             .short("v")
             .long("verbose")
             .help("Shows instruction detail")
             .takes_value(false)
             .required(false))
        .arg(clap::Arg::with_name("auto")
             .long("auto")
             .help("Disassembles file automatically")
             .conflicts_with_all(&["file offset",
                                   "string",
                                   "length",
                                   "base address"])
             .takes_value(false)
             .requires("file")
             .required(false))
        .arg(clap::Arg::with_name("file information")
             .short("i")
             .long("info")
             .help("Displays file information")
             .conflicts_with_all(&["file offset",
                                   "string",
                                   "length",
                                   "base address",
                                   "auto",
                                   "string"])
             .takes_value(false)
             .requires("file")
             .required(false))
        .arg(clap::Arg::with_name("segment")
             .long("segment")
             .help("Displays segment table")
             .takes_value(false)
             .requires("file information")
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

    if matches.is_present("file information") {
        if matches.is_present("segment") {
            let input_filename = value_t!(matches.value_of("file"), String).unwrap_or_else(|e| e.exit());

            let input_file = std::fs::File::open(input_filename.as_str())
                .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

            let mut buffer: Vec<u8> = Vec::new();

            use std::io::Read;
            let mut reader = std::io::BufReader::new(input_file);
            reader.read_to_end(&mut buffer)
                .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

            let elf_file = xmas_elf::ElfFile::new(&buffer);

            use xmas_elf::program::Type;
            use prettytable::Table;
            // use prettytable::format;

            let mut table = Table::new();
            let table_format = prettytable::format::FormatBuilder::new()
                .padding(0, 3)
                .separator(prettytable::format::LinePosition::Title,
                           prettytable::format::LineSeparator::new('=', '=', '=', '='))
                .build();
            table.set_format(table_format);

            table.add_row(row!["type", "offset", "vaddr", "paddr", "filesz", "memsz", "flags", "align"]);
            // table.add_row(row!["", "", "", "", "", "", "", ""]);

            fn segment_info(seg: xmas_elf::program::ProgramHeader) -> (String, String,
                                                                       String, String,
                                                                       String, String, String) {
                let offset_str = format!("{:#x}", seg.offset());
                let vaddr_str = format!("{:#x}", seg.virtual_addr());
                let paddr_str = format!("{:#x}", seg.physical_addr());
                let filesz_str = format!("{:#x}", seg.file_size());
                let memsz_str = format!("{:#x}", seg.mem_size());
                let flags_str = format!("{:#x}", seg.flags());
                let align_str = format!("{:#x}", seg.align());

                (offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str)
            }

            for seg in elf_file.program_iter() {
                // println!("{:?}", seg.get_type());
                match seg.get_type() {
                    Ok(seg_type) => {
                        let (offset_str, vaddr_str,
                             paddr_str, filesz_str,
                             memsz_str, flags_str, align_str) = segment_info(seg);
                        match seg_type {
                            Type::Null => {
                                table.add_row(row!["NULL"]);
                            },
                            Type::Load => {
                                table.add_row(row!["LOAD", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::Dynamic => {
                                table.add_row(row!["DYNAMIC", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::Interp => {
                                table.add_row(row!["INTERP", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::Note => {
                                table.add_row(row!["NOTE", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::ShLib => {
                                table.add_row(row!["SHLIB", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::Phdr => {
                                table.add_row(row!["PHDR", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::Tls => {
                                table.add_row(row!["TLS", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            },
                            Type::OsSpecific(t) => {
                                if t == 0x6474e550 {
                                    table.add_row(row!["GNU_EH_FRAME", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                                } else if t == 0x6474e551 {
                                    table.add_row(row!["GNU_STACK", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                                } else if t == 0x6474e552 {
                                    table.add_row(row!["GNU_RELRO", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                                }
                            }
                            _ => {
                                table.add_row(row!["UKNOWN", offset_str, vaddr_str, paddr_str, filesz_str, memsz_str, flags_str, align_str]);
                            }
                        }
                    }
                    Err(_) => {
                        table.add_row(row!["Invalid segment"]);
                    }
                }
            }

            table.printstd();
            // for seg in 

            // let nb_read = reader.read(buffer.as_mut_slice())
            //     .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });
        }
    } else {
        let mode = value_t!(matches.value_of("mode"), AddressingModes).unwrap_or_else(|e| e.exit());
        let arch = value_t!(matches.value_of("arch"), Architectures).unwrap_or_else(|e| e.exit());
        let disasm_syntax = value_t!(matches.value_of("syntax"), AssemblySyntax).unwrap_or_else(|e| e.exit());

        match mode {
            AddressingModes::x32 => {
                match arch {
                    Architectures::x86 => {
                        match disasm_syntax {
                            AssemblySyntax::intel => {
                                // let base_address = value_t!(matches.value_of("base address"), usize)
                                //     .unwrap_or_else(|e| e.exit());
                                let base_address = match matches.value_of("base address") {
                                    Some(base_address_str) => {
                                        parse_value_from_string::<usize>(base_address_str)
                                    },
                                    None => {
                                        clap::Error::argument_not_found_auto("base address").exit();
                                    }
                                };

                                let is_verbose = matches.is_present("verbose");

                                if matches.is_present("file") {
                                    let input_filename = value_t!(matches.value_of("file"), String)
                                        .unwrap_or_else(|e| e.exit());

                                    let poff = value_t!(matches.value_of("file offset"), usize)
                                        .unwrap_or_else(|e| e.exit());
                                    // let file_metadata = std::fs::metadata(input_filename.as_str()).unwrap_or_else(|e| println!("{}", e));
                                    let file_metadata = std::fs::metadata(input_filename.as_str())
                                        .unwrap_or_else(|e| { println!("{}", e); std::process::exit(1); });

                                    if file_metadata.is_file() {
                                        let file_length = file_metadata.len() as usize;

                                        if poff < file_length {
                                            let mut input_file = std::fs::File::open(input_filename.as_str())
                                                .unwrap_or_else(|e| { println!("{}", e);
                                                                      std::process::exit(1); });

                                            use std::io::Seek;
                                            input_file.seek(std::io::SeekFrom::Start(poff as u64))
                                                .unwrap_or_else(|e| { println!("{}", e);
                                                                      std::process::exit(1); });

                                            let mut buffer: Vec<u8> =
                                                match value_t!(matches.value_of("length"), usize) {
                                                    Ok(nb_to_read) => vec![0; nb_to_read],
                                                    Err(_) => vec![0; file_length - poff],
                                                };

                                            // let mut buffer: Vec<u8> = vec![];
                                            use std::io::Read;
                                            let mut reader = std::io::BufReader::new(input_file);
                                            let nb_read = reader.read(buffer.as_mut_slice())
                                                .unwrap_or_else(|e| { println!("{}", e);
                                                                      std::process::exit(1); });
                                            buffer.truncate(nb_read);

                                            disassemble_buffer(capstone::CsArch::ARCH_X86,
                                                               capstone::CsMode::MODE_32,
                                                               &buffer, base_address, is_verbose);
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
}
