use serde::{Deserialize, Serialize};

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    /// localStorage - persists across browser sessions
    Local,
    /// sessionStorage - cleared when tab/window closes
    Session,
    /// No-op mode - for when storage is disabled or unavailable
    None,
}

/// Generic browser storage abstraction that supports localStorage, sessionStorage, or no-op mode
pub struct BrowserStorage {
    storage_type: StorageType,
}

impl BrowserStorage {
    /// Create a new BrowserStorage instance with the specified storage type
    pub fn new(storage_type: StorageType) -> Self {
        Self { storage_type }
    }

    /// Get a value from storage by key
    pub fn get(&self, key: &str) -> Option<String> {
        match self.storage_type {
            StorageType::None => None,
            #[cfg(feature = "web")]
            StorageType::Local | StorageType::Session => {
                let window = web_sys::window()?;
                let storage = match self.storage_type {
                    StorageType::Local => window.local_storage().ok()??,
                    StorageType::Session => window.session_storage().ok()??,
                    StorageType::None => return None,
                };

                match storage.get_item(key) {
                    Ok(value) => value,
                    Err(e) => {
                        web_sys::console::warn_2(&format!("Failed to get item from storage: {}", key).into(), &e);
                        None
                    }
                }
            }
            #[cfg(not(feature = "web"))]
            StorageType::Local | StorageType::Session => {
                let _ = key;
                None
            }
        }
    }

    /// Set a value in storage
    pub fn set(&self, key: &str, value: &str) -> Result<(), String> {
        match self.storage_type {
            StorageType::None => Ok(()),
            #[cfg(feature = "web")]
            StorageType::Local | StorageType::Session => {
                let window = web_sys::window().ok_or_else(|| "Window not available".to_string())?;

                let storage = match self.storage_type {
                    StorageType::Local => window.local_storage().map_err(|e| format!("{:?}", e))?,
                    StorageType::Session => window.session_storage().map_err(|e| format!("{:?}", e))?,
                    StorageType::None => return Ok(()),
                }
                .ok_or_else(|| "Storage not available".to_string())?;

                storage.set_item(key, value).map_err(|e| {
                    let err_msg = format!("Failed to set item in storage '{}': {:?}", key, e);
                    web_sys::console::warn_1(&err_msg.clone().into());
                    err_msg
                })
            }
            #[cfg(not(feature = "web"))]
            StorageType::Local | StorageType::Session => {
                let _ = key;
                let _ = value;
                Ok(())
            }
        }
    }

    /// Remove a value from storage
    pub fn remove(&self, key: &str) -> Result<(), String> {
        match self.storage_type {
            StorageType::None => Ok(()),
            StorageType::Local | StorageType::Session => {
                #[cfg(feature = "web")]
                {
                    let window = web_sys::window().ok_or_else(|| "Window not available".to_string())?;

                    let storage = match self.storage_type {
                        StorageType::Local => window.local_storage().map_err(|e| format!("{:?}", e))?,
                        StorageType::Session => window.session_storage().map_err(|e| format!("{:?}", e))?,
                        StorageType::None => return Ok(()),
                    }
                    .ok_or_else(|| "Storage not available".to_string())?;

                    storage.remove_item(key).map_err(|e| {
                        let err_msg = format!("Failed to remove item from storage '{}': {:?}", key, e);
                        web_sys::console::warn_1(&err_msg.clone().into());
                        err_msg
                    })
                }
                #[cfg(not(feature = "web"))]
                {
                    let _ = key;
                    Ok(())
                }
            }
        }
    }

    /// Clear all items from storage
    pub fn clear(&self) -> Result<(), String> {
        match self.storage_type {
            StorageType::None => Ok(()),
            #[cfg(feature = "web")]
            StorageType::Local | StorageType::Session => {
                let window = web_sys::window().ok_or_else(|| "Window not available".to_string())?;

                let storage = match self.storage_type {
                    StorageType::Local => window.local_storage().map_err(|e| format!("{:?}", e))?,
                    StorageType::Session => window.session_storage().map_err(|e| format!("{:?}", e))?,
                    StorageType::None => return Ok(()),
                }
                .ok_or_else(|| "Storage not available".to_string())?;

                storage.clear().map_err(|e| {
                    let err_msg = format!("Failed to clear storage: {:?}", e);
                    web_sys::console::warn_1(&err_msg.clone().into());
                    err_msg
                })
            }
            #[cfg(not(feature = "web"))]
            StorageType::Local | StorageType::Session => Ok(()),
        }
    }

    /// Get all keys from storage
    pub fn keys(&self) -> Vec<String> {
        match self.storage_type {
            StorageType::None => Vec::new(),
            #[cfg(feature = "web")]
            StorageType::Local | StorageType::Session => {
                let window = match web_sys::window() {
                    Some(w) => w,
                    None => return Vec::new(),
                };

                let storage = match self.storage_type {
                    StorageType::Local => window.local_storage().ok().flatten(),
                    StorageType::Session => window.session_storage().ok().flatten(),
                    StorageType::None => return Vec::new(),
                };

                let storage = match storage {
                    Some(s) => s,
                    None => return Vec::new(),
                };

                let length = match storage.length() {
                    Ok(len) => len,
                    Err(_) => return Vec::new(),
                };

                let mut keys = Vec::new();
                for i in 0..length {
                    if let Ok(Some(key)) = storage.key(i) {
                        keys.push(key);
                    }
                }
                keys
            }
            #[cfg(not(feature = "web"))]
            StorageType::Local | StorageType::Session => Vec::new(),
        }
    }

    /// Get and deserialize a JSON value from storage
    pub fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        let value = self.get(key)?;
        match serde_json::from_str(&value) {
            Ok(v) => Some(v),
            #[cfg(feature = "web")]
            Err(e) => {
                web_sys::console::warn_1(&format!("Failed to parse JSON from storage key '{}': {} (value: {})", key, e, value).into());
                None
            }
            #[cfg(not(feature = "web"))]
            Err(_) => None,
        }
    }

    /// Serialize and set a JSON value in storage
    pub fn set_json<T: Serialize>(&self, key: &str, value: &T) -> Result<(), String> {
        let json = serde_json::to_string(value).map_err(|e| format!("Failed to serialize to JSON: {}", e))?;
        self.set(key, &json)
    }
}
