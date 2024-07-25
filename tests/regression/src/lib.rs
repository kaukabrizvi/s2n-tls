use s2n_tls::{
    config::Builder,
    security,
    testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler},
};
type Error = s2n_tls::error::Error;

// Function to create default config with specified parameters
pub fn set_config(
    cipher_prefs: &security::Policy,
    keypair: CertKeyPair,
) -> Result<s2n_tls::config::Config, Error> {
    let mut builder = Builder::new();
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    builder
        .load_pem(keypair.cert(), keypair.key())
        .expect("Unable to load cert/pem");
    builder.trust_pem(keypair.cert()).expect("load cert pem");
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabgrind as cg;
    use s2n_tls::testing::TestPair;
    use std::{
        env,
        fs::{create_dir, File},
        io::{self, BufRead, Write},
        path::Path,
        process::Command,
    };

    const COST: u64 = 100; // configurable threshold for regression

    struct InstrumentationControl;

    impl InstrumentationControl {
        fn stop_instrumentation(&self) {
            cg::cachegrind::stop_instrumentation();
        }

        fn start_instrumentation(&self) {
            cg::cachegrind::start_instrumentation();
        }
    }

    // Environment variable to determine whether to run under valgrind or solely test functionality
    fn is_running_under_valgrind() -> bool {
        env::var("ENABLE_VALGRIND").is_ok()
    }

    // Function to get the test suffix from environment variables
    fn get_test_suffix() -> String {
        env::var("TEST_SUFFIX").unwrap_or_else(|_| "curr".to_string())
    }

    // Function to determine if diff mode is enabled
    fn is_diff_mode() -> bool {
        env::var("DIFF_MODE").is_ok()
    }

    fn valgrind_test<F>(test_name: &str, test_body: F) -> Result<(), s2n_tls::error::Error>
    where
        F: FnOnce(&InstrumentationControl) -> Result<(), s2n_tls::error::Error>,
    {
        let suffix = get_test_suffix();
        if !is_running_under_valgrind() {
            if is_diff_mode() {
                run_diff_test(test_name);
                Ok(())
            } else {
                let ctrl = InstrumentationControl;
                test_body(&ctrl)
            }
        } else {
            run_valgrind_test(test_name, &suffix);
            Ok(())
        }
    }

    // Test to create new config, set security policy, host_callback information, load/trust certs, and build config
    #[test]
    fn test_set_config() {
        valgrind_test("test_set_config", |ctrl| {
            ctrl.stop_instrumentation();
            ctrl.start_instrumentation();
            let keypair_rsa = CertKeyPair::default();
            let _config =
                set_config(&security::DEFAULT_TLS13, keypair_rsa).expect("Failed to build config");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_rsa_handshake() {
        valgrind_test("test_rsa_handshake", |ctrl| {
            ctrl.stop_instrumentation();
            // Example usage with RSA keypair (default)
            let keypair_rsa = CertKeyPair::default();
            let config = set_config(&security::DEFAULT_TLS13, keypair_rsa)?;
            // Create a pair (client + server) using that config, start handshake measurement
            let mut pair = TestPair::from_config(&config);
            // Assert a successful handshake
            ctrl.start_instrumentation();
            assert!(pair.handshake().is_ok());
            ctrl.stop_instrumentation();
            Ok(())
        })
        .unwrap();
    }

    // Function to run specified test using valgrind
    fn run_valgrind_test(test_name: &str, suffix: &str) {
        let exe_path = std::env::args().next().unwrap();
        create_dir_all(Path::new("target/cg_artifacts")).unwrap();
        let output_file = format!(
            "target/cg_artifacts/cachegrind_{}_{}.out",
            test_name, suffix
        );
        let output_command = format!("--cachegrind-out-file={}", &output_file);
        let mut command = Command::new("valgrind");
        command
            .args(["--tool=cachegrind", &output_command, &exe_path, test_name])
            .env_remove("ENABLE_VALGRIND"); // Ensures that the recursive call is made to the actual harness code block rather than back to this function

        let status = command.status().expect("Failed to execute valgrind");

        if !status.success() {
            panic!("Valgrind failed");
        }

        let annotate_output = Command::new("cg_annotate")
            .arg(&output_file)
            .output()
            .expect("Failed to run cg_annotate");

        if !annotate_output.status.success() {
            panic!("cg_annotate failed");
        }
        create_dir_all(Path::new("target/perf_outputs")).unwrap();
        let annotate_file = format!("target/perf_outputs/{}_{}.annotated.txt", test_name, suffix);
        let mut file = File::create(&annotate_file).expect("Failed to create annotation file");
        file.write_all(&annotate_output.stdout)
            .expect("Failed to write annotation file");

        let count = grep_for_instructions(&annotate_file)
            .expect("Failed to get instruction count from file");

        println!("Instruction count for {}: {}", test_name, count);
    }

    // Function to run cg_annotate --diff and assert on the difference
    fn run_diff_test(test_name: &str) {
        let prev_file = format!("target/cg_artifacts/cachegrind_{}_prev.out", test_name);
        let curr_file = format!("target/cg_artifacts/cachegrind_{}_curr.out", test_name);

        // Check if both prev and curr files exist
        if !Path::new(&prev_file).exists() || !Path::new(&curr_file).exists() {
            panic!(
                "Required cachegrind files not found: {} or {}",
                prev_file, curr_file
            );
        }

        let diff_output = Command::new("cg_annotate")
            .args(["--diff", &prev_file, &curr_file])
            .output()
            .expect("Failed to run cg_annotate --diff");

        if !diff_output.status.success() {
            panic!("cg_annotate --diff failed");
        }

        create_dir_all(Path::new("target/perf_outputs"));
        let diff_file = format!("target/perf_outputs/{}_diff.annotated.txt", test_name);
        let mut file = File::create(&diff_file).expect("Failed to create diff annotation file");
        file.write_all(&diff_output.stdout)
            .expect("Failed to write diff annotation file");

        let diff =
            grep_for_instructions(&diff_file).expect("Failed to parse cg_annotate --diff output");

        println!("Instruction difference for {}: {}", test_name, diff);

        assert!(
            diff <= self::COST as i64,
            "Instruction count difference in {} exceeds the threshold, regression of {} instructions",
            test_name,
            diff
        );
    }

    // Parses the annotated file or diff output for the overall instruction count total
    fn grep_for_instructions(file_path: &str) -> Result<i64, io::Error> {
        let path = Path::new(file_path);
        let file = File::open(path)?;
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.contains("PROGRAM TOTALS") {
                if let Some(instructions) = line.split_whitespace().next() {
                    return instructions
                        .replace(',', "")
                        .parse::<i64>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find instruction count in annotated file",
        ))
    }
}
