use crate::discover::lexer::{tokenize, ParsedToken};

const ACTIONS: &[&str] = &[
    "build-for-testing",
    "test-without-building",
    "build",
    "analyze",
    "archive",
    "test",
    "docbuild",
    "installsrc",
    "install",
    "clean",
];

const FLAGS_CONSUME_ARG: &[&str] = &[
    "-project",
    "-target",
    "-configuration",
    "-arch",
    "-sdk",
    "-workspace",
    "-scheme",
    "-destination",
    "-destination-timeout",
    "-jobs",
    "-maximum-concurrent-test-device-destinations",
    "-maximum-concurrent-test-simulator-destinations",
    "-parallel-testing-enabled",
    "-parallel-testing-worker-count",
    "-maximum-parallel-testing-workers",
    "-toolchain",
    "-xcconfig",
    "-derivedDataPath",
    "-archivePath",
    "-resultBundlePath",
    "-resultStreamPath",
    "-resultBundleVersion",
    "-exportPath",
    "-exportOptionsPlist",
    "-localizationPath",
    "-exportLanguage",
    "-defaultLanguage",
    "-xctestrun",
    "-testProductsPath",
    "-testPlan",
    "-only-testing",
    "-skip-testing",
    "-only-test-configuration",
    "-skip-test-configuration",
    "-test-timeouts-enabled",
    "-default-test-execution-time-allowance",
    "-maximum-test-execution-time-allowance",
    "-test-iterations",
    "-test-repetition-relaunch-enabled",
    "-collect-test-diagnostics",
    "-testLanguage",
    "-testRegion",
    "-test-enumeration-style",
    "-test-enumeration-format",
    "-test-enumeration-output-path",
    "-clonedSourcePackagesDirPath",
    "-packageCachePath",
    "-packageAuthorizationProvider",
    "-defaultPackageRegistryURL",
    "-packageDependencySCMToRegistryTransformation",
    "-packageFingerprintPolicy",
    "-packageSigningEntityPolicy",
    "-authenticationKeyPath",
    "-authenticationKeyID",
    "-authenticationKeyIssuerID",
    "-scmProvider",
    "-downloadPlatform",
    "-downloadComponent",
    "-importPlatform",
    "-importComponent",
    "-deleteComponent",
    "-showComponent",
    "-platform",
    "-osVersion",
    "-modelCode",
    "-architecture",
    "-find-executable",
    "-find-library",
    "-framework",
    "-library",
    "-headers",
    "-output",
];

pub const fn flags_consume_arg() -> &'static [&'static str] {
    FLAGS_CONSUME_ARG
}

pub fn build_cmd_pattern(tokens: &[ParsedToken]) -> String {
    match find_action(tokens) {
        Some(action) => format!("xcodebuild {}", action),
        None => "xcodebuild".to_string(),
    }
}

pub fn normalize_action_command(cmd: &str) -> String {
    let tokens = tokenize(cmd);
    let Some(first) = tokens.first() else {
        return cmd.to_string();
    };
    if first.value != "xcodebuild" {
        return cmd.to_string();
    }

    build_cmd_pattern(&tokens)
}

fn find_action(tokens: &[ParsedToken]) -> Option<String> {
    let mut i = 1usize;
    while i < tokens.len() {
        let val = tokens[i].value.as_str();

        if val.starts_with('-') {
            if flag_consumes_arg(val) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        let action = val.to_ascii_lowercase();
        if ACTIONS.contains(&action.as_str()) {
            return Some(action);
        }

        // Build settings such as CODE_SIGNING_ALLOWED=NO are valid before
        // actions. Do not persist their keys or values in analytics patterns.
        i += 1;
    }

    None
}

fn flag_consumes_arg(flag: &str) -> bool {
    if flag.starts_with("-only-testing:") || flag.starts_with("-skip-testing:") {
        return false;
    }
    if flag.contains('=') {
        return false;
    }
    FLAGS_CONSUME_ARG.contains(&flag)
}
