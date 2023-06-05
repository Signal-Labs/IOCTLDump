//! Designed to work with IOCTLDump, loads the saved config/data files and replays them

use std::{env, vec};
use windows::core::PCSTR;
use windows::Win32;
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::CreateFileA;
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl;
use windows::Win32::System::IO::DeviceIoControl;

struct DeviceCallInput {
    ctrl_code: u32,
    _buffer_method: u32,
    input_buffer: Option<Vec<u8>>,
    output_buffer: Option<Vec<u8>>,
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        return show_help();
    }
    let configs_path = &args[1];
    let device_short_name = &args[2];
    return replay_saved_inputs(configs_path, device_short_name);
}

/// Enumerates the saved data in the configs path and replays them against the
/// device driver named by `device_short_name`
fn replay_saved_inputs(configs_path: &str, device_short_name: &str) {
    // configs_path may be something like `C:\DriverHooks\FileSystem\SomeDriver` or
    // 'C:\DriverHooks\Driver\SomeDriver', doesn't matter, what we care about is the
    // nested structure, e.g. '<configs_path>\devIOD\2222C0\<some_value>.(conf|data)'
    // where devIOD means we issue a DeviceIoControl call, 2222C0 is the hex control code,
    // and the same filename with different extensions contains our data (.conf is metadata relating
    // to input and output buffer sizes, .data is the raw bytes for the input buffer).

    // First lets open the device driver specified in device_short_name
    let device_path = format!(r"\\.\{}", device_short_name);
    let device_handle = match unsafe {
        CreateFileA(
            PCSTR::from_raw(device_path.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(e) => {
            println!("Failed to open device: {:?}", e);
            return;
        }
    };
    // Now that we have the device handle, we can enumerate the configs path
    // and replay the saved inputs

    // First we open the folder pointed to by configs_path
    let configs_path = std::path::Path::new(configs_path);
    let configs_dir = match std::fs::read_dir(configs_path) {
        Ok(dir) => dir,
        Err(e) => {
            println!("Failed to open configs path: {:?}", e);
            return;
        }
    };
    // We only support devIOD for now, so we'll filter out any other folders
    let deviod_dirs = configs_dir.filter(|dir| {
        let dir = match dir {
            Ok(dir) => dir,
            Err(_) => return false,
        };
        let dir_name = match dir.file_name().into_string() {
            Ok(name) => name,
            Err(_) => return false,
        };
        dir_name == "devIOD"
    });
    let mut deviod_inputs = Vec::new();
    // Now we can iterate over the devIOD folders
    for deviod_dir in deviod_dirs {
        let deviod_dir = match deviod_dir {
            Ok(dir) => dir,
            Err(e) => {
                println!("Failed to open devIOD dir: {:?}", e);
                continue;
            }
        };
        // Now we can iterate over the hex control codes
        let control_code_dirs = match std::fs::read_dir(deviod_dir.path()) {
            Ok(dir) => dir,
            Err(e) => {
                println!("Failed to open control code dir: {:?}", e);
                continue;
            }
        };
        for control_code_dir in control_code_dirs {
            let control_code_dir = match control_code_dir {
                Ok(dir) => dir,
                Err(e) => {
                    println!("Failed to open control code dir: {:?}", e);
                    continue;
                }
            };
            // Save the control_code as a u32
            let control_code =
                match u32::from_str_radix(&control_code_dir.file_name().into_string().unwrap(), 16)
                {
                    Ok(code) => code,
                    Err(e) => {
                        println!("Failed to parse control code: {:?}", e);
                        continue;
                    }
                };
            // Now we can iterate over the files in the control code dir
            let files = match std::fs::read_dir(control_code_dir.path()) {
                Ok(dir) => dir,
                Err(e) => {
                    println!("Failed to open control code dir: {:?}", e);
                    continue;
                }
            };
            for file in files {
                let file = match file {
                    Ok(file) => file,
                    Err(e) => {
                        println!("Failed to open file: {:?}", e);
                        continue;
                    }
                };
                let file_name = match file.file_name().into_string() {
                    Ok(name) => name,
                    Err(e) => {
                        println!("Failed to get file name: {:?}", e);
                        continue;
                    }
                };
                // We only care about .conf files, as we will manually load the corresponding
                // .data files during parsing
                if file_name.ends_with(".conf") {
                    // Read the conf file
                    let conf_file = match std::fs::read_to_string(file.path()) {
                        Ok(file) => file,
                        Err(e) => {
                            println!("Failed to read conf file: {:?}", e);
                            continue;
                        }
                    };
                    // Convert the utf-16 encoded string
                    let u16_bytes: Vec<u16> = conf_file
                        .as_bytes()
                        .chunks_exact(2)
                        .into_iter()
                        .map(|a| u16::from_ne_bytes([a[0], a[1]]))
                        .collect();
                    let conf_file = match String::from_utf16(&u16_bytes) {
                        Ok(file) => file,
                        Err(e) => {
                            println!("Failed to convert conf file from utf-16: {:?}", e);
                            continue;
                        }
                    };

                    // The format of the .conf file is:
                    // <driver_name>
                    // <type>
                    // <buffer method>
                    // <ioctl code>
                    // <input buffer size>
                    // <output buffer size>
                    // these are separated by newlines (\n)
                    // We only care about the buffer method, ioctl code, input buffer size and output buffer size
                    println!("\nParsing conf file: {}\n", conf_file);
                    let conf_file = conf_file.split("\r\n").collect::<Vec<&str>>();

                    let buffer_method = conf_file[2].replace("BuffType:", "");
                    let input_buffer_size = conf_file[4].replace("InputBufferLength:", "");
                    let output_buffer_size = conf_file[5].replace("OutputBufferLength:", "");
                    // print the buffer method, ioctl code, input buffer size and output buffer size
                    println!(
                        "Buffer method: {}\nIoctl code: {:#x}\nInput buffer size: {}\nOutput buffer size: {}\n",
                        buffer_method, control_code, input_buffer_size, output_buffer_size
                    );
                    // Now we can parse the buffer method, by matching on the string and
                    // converting it to the appropriate enum value
                    // We expect values such as "BuffType:METHOD_BUFFERED"
                    let buffer_method = match buffer_method.as_str() {
                        "METHOD_BUFFERED" => Ioctl::METHOD_BUFFERED,
                        "METHOD_IN_DIRECT" => Ioctl::METHOD_IN_DIRECT,
                        "METHOD_OUT_DIRECT" => Ioctl::METHOD_OUT_DIRECT,
                        "METHOD_NEITHER" => Ioctl::METHOD_NEITHER,
                        _ => {
                            println!("Unknown buffer method: {}", buffer_method);
                            continue;
                        }
                    };
                    // Now we can parse the input buffer size and output buffer size
                    let input_buffer_size =
                        match u32::from_str_radix(input_buffer_size.as_str(), 16) {
                            Ok(size) => size,
                            Err(e) => {
                                println!("Failed to parse input buffer size: {:?}", e);
                                continue;
                            }
                        };
                    let output_buffer_size =
                        match u32::from_str_radix(output_buffer_size.as_str(), 16) {
                            Ok(size) => size,
                            Err(e) => {
                                println!("Failed to parse output buffer size: {:?}", e);
                                continue;
                            }
                        };
                    // Read the corresponding .data file into a buffer, this will be our input buffer
                    // bytes

                    let data_file = {
                        if input_buffer_size != 0 {
                            match std::fs::read(file.path().with_extension("data")) {
                                Ok(file) => Some(file),
                                Err(e) => {
                                    println!("Failed to read data file: {:?}", e);
                                    continue;
                                }
                            }
                        } else {
                            None
                        }
                    };
                    //println!("File name: {:?}, file bytes: {:#x?}", file_name, data_file);
                    let output_buffer = {
                        if output_buffer_size != 0 {
                            Some(vec![0u8; output_buffer_size as usize])
                        } else {
                            None
                        }
                    };
                    // Now we can create the DeviceCallInput
                    let dev_call_input = DeviceCallInput {
                        ctrl_code: control_code,
                        _buffer_method: buffer_method,
                        input_buffer: data_file,
                        output_buffer: output_buffer,
                    };
                    deviod_inputs.push(dev_call_input);
                }
            }
        }
    }
    // Finished enumerating the contents of configs_path
    // Go through all our inputs and call the driver with them
    replay_parsed_inputs(&mut deviod_inputs, device_handle);
}

/// Replays parsed inputs
fn replay_parsed_inputs(
    deviod_inputs: &mut Vec<DeviceCallInput>,
    device_handle: Win32::Foundation::HANDLE,
) {
    for input in deviod_inputs {
        // Call the driver with the input
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                device_handle,
                input.ctrl_code,
                input
                    .input_buffer
                    .as_ref()
                    .map_or(Some(std::ptr::null()), |x| Some(x.as_ptr() as *const _)),
                input.input_buffer.as_ref().map_or(0, |x| x.len()) as u32,
                input
                    .output_buffer
                    .as_mut()
                    .map_or(Some(std::ptr::null_mut()), |x| {
                        Some(x.as_mut_ptr() as *mut _)
                    }),
                input.output_buffer.as_ref().map_or(0, |x| x.len()) as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        if result.as_bool() {
            println!(
                "Successfully called driver with control code: {:x}",
                input.ctrl_code
            );
            /*
            match bytes_returned {
                0 => println!("No bytes returned"),
                _ => println!("Bytes returned: {:#x?}", input.output_buffer.as_ref().unwrap()),
            }
            */
        } else {
            println!(
                "Failed to call driver with control code: {:x}",
                input.ctrl_code
            );
        }
    }
    println!("Finished replaying inputs");
}

/// Prints the usage for this tool
fn show_help() {
    println!("USAGE: ioctl_replayer.exe <path_to_saved_info> <device_name>");
    println!("E.g.: ioctl_replayer.exe C:\\DriverHooks\\Driver\\mydrv mydrv_device");
    println!("where \\\\.\\mydrv_device is a valid path.");
}
