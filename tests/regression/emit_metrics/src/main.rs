use aws_sdk_cloudwatch::{Client as CloudWatchClient, types::{Dimension, MetricDatum}};
use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_smithy_types::DateTime;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::process::Command;
use glob::glob;

#[tokio::main]
async fn main() {
    // Fetch the latest commit ID from the environment
    let commit_id = get_latest_commit_id();

    // Construct the directory path
    let dir_path = format!("../target/{}", commit_id);
    let pattern = format!("{}/{}.annotated", dir_path, "*");

    // Load the AWS SDK configuration
    let region = RegionProviderChain::first_try("us-west-2");

    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .load()
        .await;

    let cloudwatch_client = aws_sdk_cloudwatch::Client::new(&config);

    // Iterate over the annotated files in the latest commit directory
    for entry in glob(&pattern).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let file_path = path.to_str().unwrap();
                let test_name = extract_test_name(file_path);

                // Find the instruction count from the file
                match find_instruction_count(file_path) {
                    Ok(count) => {
                        // Process and send the data to CloudWatch
                        send_to_cloudwatch(&cloudwatch_client, &test_name, count).await;
                    },
                    Err(e) => eprintln!("Failed to find instruction count in {}: {}", file_path, e),
                }
            }
            Err(e) => eprintln!("Error reading path: {}", e),
        }
    }
}

fn get_latest_commit_id() -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Failed to get commit hash");

    if !output.status.success() {
        panic!("Git command failed");
    }

    String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 in commit hash")
        .trim()
        .to_string()
}

fn extract_test_name(file_path: &str) -> String {
    Path::new(file_path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .to_string()
}

pub fn find_instruction_count(file_path: &str) -> Result<i64, io::Error> {
    let file = File::open(file_path)?;
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
    panic!("Failed to find instruction count in annotated file");
}

async fn send_to_cloudwatch(client: &CloudWatchClient, test_name: &str, count: i64) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
    let timestamp = DateTime::from_secs(now.as_secs() as i64);

    let test_name_dimension = Dimension::builder()
        .name("TestName")
        .value(test_name)
        .build();

    let datum = MetricDatum::builder()
        .metric_name("InstructionCount")
        .value(count as f64)
        .timestamp(timestamp)
        .dimensions(test_name_dimension)
        .build();

    let request = client.put_metric_data()
        .namespace("MyApp/Performance")
        .metric_data(datum)
        .send()
        .await;

    match request {
        Ok(_) => println!("Successfully sent data for test: {}: {} instructions", test_name, count),
        Err(e) => eprintln!("Failed to send data: {}", e),
    }
}
