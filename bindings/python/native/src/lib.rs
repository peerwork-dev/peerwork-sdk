use pyo3::prelude::*;

#[pyfunction]
fn version() -> &'static str {
    peerwork_core::version()
}

#[pyfunction]
fn capabilities_json() -> PyResult<String> {
    serde_json::to_string(&peerwork_core::capability_manifest())
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("manifest serialization failed"))
}

#[pymodule]
fn _peerwork_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(capabilities_json, module)?)?;
    Ok(())
}
