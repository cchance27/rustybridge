use rb_web::app_root::app_root;

fn main() {
    // Initialize platform-specific logging
    rb_web::app::logging::init();
    dioxus::launch(app_root);
}
