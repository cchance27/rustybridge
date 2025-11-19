use std::collections::HashMap;

use crate::TuiApp;

/// Factory function type for creating TUI apps
pub type AppFactory = Box<dyn Fn() -> Box<dyn TuiApp> + Send + Sync>;

/// Registry for mapping names to TUI app factories
pub struct AppRegistry {
    apps: HashMap<String, AppFactory>,
    default: Option<AppFactory>,
}

impl AppRegistry {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            default: None,
        }
    }

    /// Register an app factory under a name
    pub fn register(&mut self, name: impl Into<String>, factory: impl Fn() -> Box<dyn TuiApp> + Send + Sync + 'static) {
        self.apps.insert(name.into(), Box::new(factory));
    }

    /// Set the default app factory
    pub fn set_default(&mut self, factory: impl Fn() -> Box<dyn TuiApp> + Send + Sync + 'static) {
        self.default = Some(Box::new(factory));
    }

    /// Get an app instance by name, falling back to default if not found
    pub fn get_app(&self, name: &str) -> Option<Box<dyn TuiApp>> {
        if let Some(factory) = self.apps.get(name) {
            Some(factory())
        } else if let Some(factory) = &self.default {
            Some(factory())
        } else {
            None
        }
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}
