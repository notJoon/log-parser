use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref NUMERIC: Regex = Regex::new(r"^\d+$").unwrap();
    static ref DATE: Regex = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap(); // YYYY-MM-DD
    static ref TIME: Regex = Regex::new(r"^\d{2}:\d{2}:\d{2}$").unwrap(); // HH:MM:SS
    static ref UUID: Regex = Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
}

/// Extracts templates from log entries by replacing numbers, dates, and UUIDs with placeholders.
/// Returns a vector of the processed templates.
///
/// # Arguments
/// * `logs` - A vector of strings, each a raw log entry.
///
/// # Returns
/// * A vector of strings, each a templated version of the input logs.
pub fn extract_templates(logs: Vec<String>) -> Vec<String> {
    logs.iter()
        .map(|log| {
            process_log_parts(log)
        })
        .collect()
}

fn process_log_parts(log: &String) -> String {
    log.split_whitespace()
        .map(|part| {
            has_pattern(part)
        })
        .collect::<Vec<String>>()
        .join(" ")
}

fn has_pattern(part: &str) -> String {
    if NUMERIC.is_match(part) {
        "<NUM>".to_string()
    } else if DATE.is_match(part) {
        "<DATE>".to_string()
    } else if UUID.is_match(part) {
        "<ID>".to_string()
    } else if TIME.is_match(part) {
        "<NUM>:<NUM>:<NUM>".to_string()
    } else {
        part.to_string()
    }
}

/// Extracts templates from a collection of log entries using a user-defined regex.
/// The function validates the regex for safety and performance before applying it.
/// Returns a map of templates with their occurrence counts.
///
/// # Arguments
/// * `logs` - A vector of strings, each representing a log entry.
/// * `pattern` - A string slice containing the regex pattern.
/// * `tag` - A tag to replace the matched sections in the logs.
///
/// # Returns
/// * `Ok(HashMap<String, usize>)` with templates and their counts,
/// * `Err(&'static str)` if the regex pattern is invalid or too complex.
pub fn extract_custom_template(
    logs: Vec<String>,
    pattern: &str,
    tag: &str,
) -> Result<HashMap<String, usize>, &'static str> {
    let custom_regex = validate_regex(pattern)?;
    let mut templates = HashMap::new();

    for log in logs {
        let template = inject_custom_template(&log, &custom_regex, tag);
        *templates.entry(template).or_insert(0) += 1;
    }

    Ok(templates)
}

/// Validates the user-provided regex pattern for safety and simplicity.
/// Returns an error if the pattern exceeds complexity limits or is invalid.
///
/// # Arguments
/// * `pattern` - A string slice that holds the regex pattern to validate.
///
/// # Returns
/// * `Ok(Regex)` if the pattern is valid,
/// * `Err(&'static str)` if the pattern is too complex or invalid.
fn validate_regex(pattern: &str) -> Result<Regex, &'static str> {
    if pattern.len() > 100 {
        Err("Regex pattern is too complex")
    } else {
        Regex::new(pattern).map_err(|_| "Invalid regex pattern")
    }
}

/// Applies a validated regex to replace matched sections in a log entry with a custom tag.
/// Implements a timeout to prevent excessive processing time.
///
/// # Arguments
/// * `log` - A string slice of the log entry.
/// * `custom_reg` - A reference to the compiled Regex.
/// * `tag` - A tag to replace the matched sections with.
///
/// # Returns
/// * A String with the matched sections replaced by the custom tag.
fn inject_custom_template(log: &str, custom_reg: &Regex, tag: &str) -> String {
    let timeout = Duration::from_secs(1);
    let start = Instant::now();
    let mut modified_log = log.to_string();

    while let Some(mat) = custom_reg.find(&modified_log) {
        if start.elapsed() > timeout {
            break;
        }
        modified_log.replace_range(mat.range(), format!("<{}>", tag).as_str());
    }

    modified_log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_templates() {
        struct TestCase {
            name: &'static str,
            logs: Vec<String>,
            expected: Vec<String>,
        }

        let tests = vec![
            TestCase {
                name: "Test with dates",
                logs: vec![
                    "User 123456 logged in on 2021-06-01".to_string(),
                    "User 654321 logged in on 2021-07-02".to_string(),
                ],
                expected: vec![
                    "User <NUM> logged in on <DATE>".to_string(),
                    "User <NUM> logged in on <DATE>".to_string(),
                ],
            },
            TestCase {
                name: "Test with UUIDs",
                logs: vec![
                    "Session 3f2b4f44-4b44-4b44-9c91-dddddddddddd started".to_string(),
                    "Session a1b2c3d4-1234-5678-9abc-ffffffffffff ended".to_string(),
                ],
                expected: vec![
                    "Session <ID> started".to_string(),
                    "Session <ID> ended".to_string(),
                ],
            },
            TestCase {
                name: "Test with mixed content",
                logs: vec![
                    "File report.pdf uploaded by user 12345 at 2020-01-01 10:00:00".to_string(),
                    "File summary.txt uploaded by user 67890 at 2020-02-01 15:00:00".to_string(),
                ],
                expected: vec![
                    "File report.pdf uploaded by user <NUM> at <DATE> <NUM>:<NUM>:<NUM>"
                        .to_string(),
                    "File summary.txt uploaded by user <NUM> at <DATE> <NUM>:<NUM>:<NUM>"
                        .to_string(),
                ],
            },
        ];

        for tt in tests {
            let templates = extract_templates(tt.logs);
            assert_eq!(
                templates, tt.expected,
                "Failed test '{}': Expected {:?}, got {:?}",
                tt.name, tt.expected, templates
            );
        }
    }

    #[test]
    fn test_custom_regex_with_file_extensions() {
        let logs = vec![
            "User downloaded report.pdf from server".to_string(),
            "Backup created as backup.zip on 2021-06-01".to_string(),
            "Image uploaded: picture.png".to_string(),
        ];

        let pattern = r"\.\w+";

        match extract_custom_template(logs, pattern, "FILE") {
            Ok(templates) => {
                let mut expected = HashMap::new();
                expected.insert("User downloaded report<FILE> from server".to_string(), 1);
                expected.insert(
                    "Backup created as backup<FILE> on 2021-06-01".to_string(),
                    1,
                );
                expected.insert("Image uploaded: picture<FILE>".to_string(), 1);

                assert_eq!(
                    templates, expected,
                    "Templates do not match expected output."
                );
            }
            Err(err) => panic!("Failed with error: {}", err),
        }
    }
}
