#[test]
fn dependencies_link() {
    let flags = argent_runtime::covenant_engine_flags();
    assert!(flags.covenants_enabled);
}
