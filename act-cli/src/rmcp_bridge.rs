use crate::runtime;
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};

#[allow(dead_code)]
pub struct ActRmcpBridge {
    pub handle: runtime::ComponentHandle,
    pub info: runtime::ComponentInfo,
    pub metadata: runtime::Metadata,
    pub metadata_schema: Option<String>,
}

impl ServerHandler for ActRmcpBridge {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(self.info.std.name.clone(), self.info.std.version.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_info() -> runtime::ComponentInfo {
        let mut info = runtime::ComponentInfo::default();
        info.std.name = "example".to_string();
        info.std.version = "1.2.3".to_string();
        info
    }

    fn fake_handle() -> runtime::ComponentHandle {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx
    }

    #[test]
    fn get_info_exposes_server_name_version_and_tools_capability() {
        let bridge = ActRmcpBridge {
            handle: fake_handle(),
            info: fake_info(),
            metadata: runtime::Metadata::default(),
            metadata_schema: None,
        };
        let info = rmcp::ServerHandler::get_info(&bridge);
        assert_eq!(info.server_info.name, "example");
        assert_eq!(info.server_info.version, "1.2.3");
        assert!(
            info.capabilities.tools.is_some(),
            "tools capability must be advertised"
        );
    }
}
