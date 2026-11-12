//! Conservative argv grammars for JavaScript runtimes. Add supported syntax to
//! a runtime's table, with positive and ambiguous-command regression cases.
//! Unknown flags, inline code, tasks, remote modules and relative entry points
//! deliberately remain unresolved. These tables describe syntax, not trust:
//! callers must still canonicalize and hash the script before persisting a rule.

struct Syntax {
    run_subcommand: bool,
    flags: &'static [&'static str],
    values: &'static [&'static str],
    /// Optional values must use `=value`; a following token is the script.
    optional_values: &'static [&'static str],
}

// https://nodejs.org/api/cli.html
const NODE: Syntax = Syntax {
    run_subcommand: false,
    flags: &[
        "--experimental-vm-modules",
        "--experimental-import-meta-resolve",
        "--experimental-require-module",
        "--experimental-strip-types",
        "--no-experimental-strip-types",
        "--enable-source-maps",
        "--no-warnings",
        "--no-deprecation",
        "--trace-warnings",
        "--trace-deprecation",
        "--abort-on-uncaught-exception",
        "--preserve-symlinks",
        "--preserve-symlinks-main",
        "--cpu-prof",
        "--heap-prof",
    ],
    values: &[
        "--conditions",
        "-C",
        "--require",
        "-r",
        "--import",
        "--loader",
        "--experimental-loader",
        "--inspect-port",
        "--unhandled-rejections",
        "--max-old-space-size",
        "--max-semi-space-size",
        "--stack-size",
        "--cpu-prof-dir",
        "--cpu-prof-name",
        "--cpu-prof-interval",
        "--heap-prof-dir",
        "--heap-prof-name",
        "--heap-prof-interval",
        "--diagnostic-dir",
    ],
    optional_values: &["--inspect", "--inspect-brk", "--inspect-wait"],
};

// https://bun.sh/docs/runtime
const BUN: Syntax = Syntax {
    run_subcommand: true,
    flags: &[
        "--watch",
        "--hot",
        "--no-clear-screen",
        "--no-install",
        "--prefer-offline",
        "--prefer-latest",
        "--preserve-symlinks",
        "--preserve-symlinks-main",
        "--no-macros",
    ],
    values: &[
        "--preload",
        "--require",
        "-r",
        "--import",
        "--conditions",
        "--env-file",
        "--cwd",
        "--config",
        "-c",
        "--tsconfig-override",
        "--loader",
        "-l",
        "--define",
        "-d",
        "--install",
    ],
    optional_values: &["--inspect", "--inspect-brk", "--inspect-wait"],
};

// https://docs.deno.com/runtime/reference/cli/run/
const DENO: Syntax = Syntax {
    run_subcommand: true,
    flags: &[
        "-A",
        "--allow-all",
        "--no-prompt",
        "--no-config",
        "--no-lock",
        "--cached-only",
        "--quiet",
        "-q",
    ],
    values: &[
        "--config",
        "-c",
        "--import-map",
        "--cert",
        "--location",
        "--v8-flags",
        "--seed",
        "--conditions",
    ],
    optional_values: &[
        "--allow-read",
        "--allow-write",
        "--allow-net",
        "--allow-env",
        "--allow-run",
        "--allow-ffi",
        "--allow-sys",
        "--allow-import",
        "--deny-read",
        "--deny-write",
        "--deny-net",
        "--deny-env",
        "--deny-run",
        "--deny-ffi",
        "--deny-sys",
        "--watch",
        "--check",
        "--no-check",
        "--reload",
        "--node-modules-dir",
        "--inspect",
        "--inspect-brk",
        "--inspect-wait",
    ],
};

pub(super) fn extract_script<'a>(args: &'a [String], runtime: &str) -> Option<&'a str> {
    let syntax = match runtime {
        "node" | "nodejs" => &NODE,
        "bun" => &BUN,
        "deno" => &DENO,
        _ => return None,
    };
    let mut it = args.iter().skip(1);
    let mut saw_run = false;
    while let Some(arg) = it.next() {
        if arg == "--" {
            return absolute_entry(it.next()?);
        }
        if arg == "run" && syntax.run_subcommand && !saw_run {
            saw_run = true;
            continue;
        }
        if !arg.starts_with('-') {
            return absolute_entry(arg);
        }
        let (option, attached) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(option, value)| {
                (option, Some(value))
            });
        if syntax.values.contains(&option) {
            let value = attached.or_else(|| it.next().map(String::as_str))?;
            if value.is_empty() || value.starts_with('-') {
                return None;
            }
        } else if syntax.optional_values.contains(&option) {
            if attached.is_some_and(str::is_empty) {
                return None;
            }
        } else if !syntax.flags.contains(&option) || attached.is_some() {
            return None;
        }
    }
    None
}

fn absolute_entry(arg: &str) -> Option<&str> {
    std::path::Path::new(arg).is_absolute().then_some(arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(runtime: &str, args: &[&str]) -> Option<String> {
        let args: Vec<_> = std::iter::once(runtime)
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect();
        extract_script(&args, runtime).map(str::to_owned)
    }

    #[test]
    fn resolves_worker_commands_and_consumes_option_values() {
        for (runtime, args) in [
            (
                "node",
                vec![
                    "--conditions",
                    "node",
                    "--conditions",
                    "development",
                    "/worker.js",
                ],
            ),
            (
                "nodejs",
                vec![
                    "--experimental-vm-modules",
                    "--enable-source-maps",
                    "/worker.js",
                ],
            ),
            (
                "node",
                vec![
                    "--require",
                    "/preload.js",
                    "--import=/loader.mjs",
                    "/worker.js",
                ],
            ),
            (
                "node",
                vec![
                    "-C",
                    "development",
                    "-r",
                    "/preload.js",
                    "--inspect=127.0.0.1:9229",
                    "/worker.js",
                ],
            ),
            (
                "bun",
                vec!["--hot", "run", "--preload", "/preload.js", "/worker.js"],
            ),
            ("bun", vec!["--conditions=development", "/worker.js"]),
            (
                "deno",
                vec![
                    "run",
                    "--allow-read",
                    "--allow-env=HOME",
                    "--config",
                    "/deno.json",
                    "/worker.js",
                ],
            ),
            (
                "deno",
                vec!["--quiet", "run", "--watch", "--inspect", "/worker.js"],
            ),
            ("deno", vec!["-A", "/worker.js"]),
        ] {
            assert_eq!(
                parse(runtime, &args).as_deref(),
                Some("/worker.js"),
                "{runtime} {args:?}"
            );
        }
    }

    #[test]
    fn rejects_ambiguous_or_non_file_commands() {
        for runtime in ["node", "nodejs", "bun", "deno"] {
            for args in [
                vec![],
                vec!["worker.js"],
                vec!["./worker.js"],
                vec!["-"],
                vec!["--unknown", "/value", "/worker.js"],
                vec!["--eval", "/worker.js"],
                vec!["-e", "/worker.js"],
                vec!["--print", "/worker.js"],
                vec!["--conditions"],
                vec!["--conditions=", "/worker.js"],
                vec!["--conditions", "--", "/worker.js"],
                vec!["test", "/worker.js"],
                vec!["task", "/worker.js"],
                vec!["run", "dev", "/worker.js"],
                vec!["run", "https://example.com/worker.js"],
            ] {
                assert_eq!(parse(runtime, &args), None, "{runtime} {args:?}");
            }
        }
    }

    #[test]
    fn stops_parsing_at_entry_or_double_dash() {
        for runtime in ["node", "bun", "deno"] {
            assert_eq!(
                parse(runtime, &["--", "/worker.js", "--eval"]).as_deref(),
                Some("/worker.js")
            );
            assert_eq!(
                parse(runtime, &["/worker.js", "--unknown"]).as_deref(),
                Some("/worker.js")
            );
            assert_eq!(parse(runtime, &["--"]), None);
            assert_eq!(parse(runtime, &["--", "worker.js"]), None);
        }
    }
}
