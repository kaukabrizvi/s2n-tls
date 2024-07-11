use crabgrind as cg;

fn main() {
    cg::cachegrind::stop_instrumentation();
    cg::cachegrind::start_instrumentation();
    let builder = regression::create_empty_config();
    builder.ok();
}
