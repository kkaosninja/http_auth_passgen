use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
};

//TODO: Take these values from the user, instead of using pre-defined ones
const USERNAME: &str = "admin";
const PASSWORDS_WORDLIST_FILENAME: &str = "passwords.txt";
const OUTPUT_FILE_NAME: &str = "output.txt";

fn main() {
    println!("--BEGIN PROGRAM--");

    // Open the wordlist file containing passwords
    let input_file_handle = File::open(PASSWORDS_WORDLIST_FILENAME).expect("Error in reading file");
    let input_file_lines = BufReader::new(input_file_handle).lines();

    // Create/Open the output file where we are going to the put the Base64 encoded Auth strings
    let output_file_handle = OpenOptions::new()
        .append(true)
        .create(true)
        .open(OUTPUT_FILE_NAME)
        .expect("Unable to create/open output file");

    let mut output_file_writer = BufWriter::new(output_file_handle);

    /* For each password from the wordlist, we combine the username, a colon sign, and a password,
        Base64 encode them, and write it out to the output file.

        For Each Password Wordlist Line
            Write-Out( Base64-Encode( "user:pass" ) )
    */
    for line in input_file_lines {
        if let Ok(password) = line {
            let auth_str = get_base64_auth_str(String::from(USERNAME), password);
            output_file_writer
                .write_all(auth_str.as_bytes())
                .expect("Could not write output line for password:");
            output_file_writer
                .write_all("\n".as_bytes())
                .expect("Could not write output line for password:");
        }
    }

    //Flush Output File Write buffer
    output_file_writer
        .flush()
        .expect("Unable to flush output file writer buffer!");

    println!("--END PROGRAM--");
    println!("Good luck with HTTP Auth Brute Force! 😎")
}

fn get_base64_auth_str(username: String, password: String) -> String {
    let mut auth_str_unencoded = String::new();

    auth_str_unencoded.push_str(username.as_str());
    auth_str_unencoded.push(':');
    auth_str_unencoded.push_str(password.as_str());

    return base64::encode(auth_str_unencoded);
}
