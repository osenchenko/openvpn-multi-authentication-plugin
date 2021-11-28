use slog::o;
use slog::Drain;
extern crate slog_async;
extern crate slog_term;
use std::fs::OpenOptions;

pub const LOG_LEVEL_DEBUG: &'static str = "DEBUG";
pub const LOG_LEVEL_WARN: &'static str = "WARN";
pub const LOG_LEVEL_INFO: &'static str = "INFO";
// pub const LOG_LEVEL_ERROR: &'static str = "ERROR";

pub fn create_logger(log_file: String, log_level: String) -> Result<slog::Logger, std::io::Error> {
    let log_level = match log_level.to_ascii_uppercase().as_str() {
        // LOG_LEVEL_ERROR => slog::Level::Error,
        LOG_LEVEL_INFO => slog::Level::Info,
        LOG_LEVEL_WARN => slog::Level::Warning,
        LOG_LEVEL_DEBUG => slog::Level::Trace,
        _ => slog::Level::Info,
    };

    // log::set_max_level(log_level);
    let decorator = slog_term::PlainDecorator::new(std::io::stdout());
    let drain_term = slog_term::FullFormat::new(decorator).build().fuse();
    let drain_term = slog_async::Async::new(drain_term).build().fuse();
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_file)
        .unwrap();
    let decorator = slog_term::PlainDecorator::new(file);
    let drain_file = slog_term::FullFormat::new(decorator).build().fuse();
    let drain_file = slog_async::Async::new(drain_file).build().fuse();
    let log = slog::Logger::root(
        slog::Duplicate::new(
            slog::LevelFilter::new(drain_term, slog::Level::Error),
            slog::LevelFilter::new(drain_file, log_level),
        )
        .fuse(),
        o!(),
    );

    let logger = log.new(o!());
    Ok(logger)
}
