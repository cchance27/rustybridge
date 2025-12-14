#[cfg(feature = "web")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "web")]
#[wasm_bindgen]
extern "C" {
    /// Fits the terminal with the given ID to its container
    #[wasm_bindgen(js_namespace = window, js_name = fitTerminal)]
    pub fn fit_terminal(id: &str);

    /// Focuses the terminal with the given ID
    #[wasm_bindgen(js_namespace = window, js_name = focusTerminal)]
    pub fn focus_terminal(id: &str);

    /// Initializes the RustyBridge terminal
    #[wasm_bindgen(js_namespace = window, js_name = initRustyBridgeTerminal, catch)]
    pub async fn init_rusty_bridge_terminal(id: &str, options: &JsValue) -> Result<JsValue, JsValue>;

    /// Gets the terminal dimensions
    #[wasm_bindgen(js_namespace = window, js_name = getTerminalDimensions)]
    pub fn get_terminal_dimensions(id: &str) -> JsValue;

    /// Sets up terminal input handling
    #[wasm_bindgen(js_namespace = window, js_name = setupTerminalInput, catch)]
    pub fn setup_terminal_input(id: &str, callback: &Closure<dyn FnMut(JsValue)>) -> Result<bool, JsValue>;

    /// Sets up terminal resize handling
    #[wasm_bindgen(js_namespace = window, js_name = setupTerminalResize, catch)]
    pub fn setup_terminal_resize(id: &str, callback: &Closure<dyn FnMut(JsValue)>) -> Result<bool, JsValue>;

    /// Writes data to the terminal
    #[wasm_bindgen(js_namespace = window, js_name = writeToTerminal)]
    pub fn write_to_terminal(id: &str, data: &[u8]);
}
