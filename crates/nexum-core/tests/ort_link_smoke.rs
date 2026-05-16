//! Smoke test: `ort` is linkable from nexum-core. Confirms the crate
//! dependency wiring + the `download-binaries` build feature both work
//! end-to-end (cargo can resolve, download the ONNX Runtime binary, and
//! link it).

#[test]
fn ort_session_builder_constructs() {
    let _builder = ort::session::Session::builder().expect("ort builder constructs");
}
