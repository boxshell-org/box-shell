//! box-shell entry point — port of cli/cli.c `main()`.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // `proot --shm-helper` — detached sysvipc backing-fd daemon.
    if args.len() == 2 && args[1] == "--shm-helper" {
        boxshell::extension::sysvipc::shm::shm_helper_main();
    }

    // Pre-create the first tracee (pid == 0 placeholder).
    let tracee = match boxshell::tracee::get_tracee(0, true) {
        Some(t) => t,
        None => {
            eprintln!("fatal error: can't allocate the first tracee");
            std::process::exit(libc::EXIT_FAILURE);
        }
    };

    let status = boxshell::cli::run(&tracee, &args);
    if status < 0 {
        if boxshell::cli::EXIT_FAILURE.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("fatal error: see `proot --help`.");
            std::process::exit(libc::EXIT_FAILURE);
        }
        std::process::exit(libc::EXIT_SUCCESS);
    }
    std::process::exit(status);
}
