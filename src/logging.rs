use core::{cell::UnsafeCell, fmt::Write};

use log::{set_logger, set_max_level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use uart_16550::SerialPort;

pub unsafe fn init() -> Result<(), SetLoggerError> {
    LOGGER.init();
    set_max_level(LevelFilter::Trace);
    set_logger(&LOGGER)
}

static LOGGER: Logger = Logger(UnsafeCell::new(unsafe { SerialPort::new(0x3f8) }));

struct Logger(UnsafeCell<SerialPort>);

impl Logger {
    /// # Safety
    ///
    /// This function must not be called while the logger is already in use.
    unsafe fn init(&self) {
        (&mut *self.0.get()).init();
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let port = unsafe {
            // SAFETY: No.
            &mut *self.0.get()
        };
        let _ = writeln!(port, "{}", record.args());
    }

    fn flush(&self) {}
}

unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}
