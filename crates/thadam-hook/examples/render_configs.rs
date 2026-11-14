//! Prints each tool's hook configuration as `install-hooks` would write it (no files are
//! written), for review before installing.

fn main() {
    for adapter in thadam_hook::adapters::ALL {
        println!("== {}", adapter.config.path);
        print!(
            "{}",
            (adapter.config.render)(thadam_hook::install::HOOK_BIN)
        );
    }
}
