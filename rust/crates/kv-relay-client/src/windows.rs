//! Windows SCM integration using the workspace's existing windows-service dependency.

use std::{ffi::OsString, path::Path, time::Duration};

use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceDependency, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceSidType, ServiceStartType, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{
    error::{Error, Result},
    platform,
};

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(platform::service_name(), ffi_service_main).map_err(|_| Error::Config)
}

define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: if state == ServiceState::StopPending {
            1
        } else {
            0
        },
        wait_hint: Duration::from_secs(15),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let (shutdown, receiver) = watch::channel(false);
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = shutdown.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(platform::service_name(), handler) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        let _ = handle.set_service_status(status(ServiceState::Stopped, 1));
        return;
    };
    if handle
        .set_service_status(status(ServiceState::Running, 0))
        .is_err()
    {
        return;
    }
    let mut stopping = receiver.clone();
    let result = runtime.block_on(async {
        let stop_status = async {
            crate::client::stopped(&mut stopping).await;
            let _ = handle.set_service_status(status(ServiceState::StopPending, 0));
        };
        tokio::pin!(stop_status);
        let daemon = crate::process::run_daemon(receiver);
        tokio::pin!(daemon);
        tokio::select! {
            result = &mut daemon => result,
            _ = &mut stop_status => daemon.await,
        }
    });
    let _ = handle.set_service_status(status(ServiceState::Stopped, u32::from(result.is_err())));
}

fn service_info() -> ServiceInfo {
    let name = platform::service_name();
    ServiceInfo {
        name: name.clone().into(),
        display_name: "KeyValet Remote Approval Relay".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: Path::new(kv_platform::paths::RELAY_BIN).to_path_buf(),
        launch_arguments: vec!["--service".into()],
        dependencies: vec![ServiceDependency::Service(
            kv_platform::paths::SERVICE_NAME.into(),
        )],
        account_name: Some(kv_platform::paths::RELAY_SERVICE_ACCOUNT.into()),
        account_password: None,
    }
}

pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|_| Error::Config)?;
    let service = manager
        .create_service(
            &service_info(),
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(|_| Error::Config)?;
    service
        .set_description("Transports encrypted helper envelopes to the KeyValet relay.")
        .map_err(|_| Error::Config)?;
    service
        .set_config_service_sid_info(ServiceSidType::Unrestricted)
        .map_err(|_| Error::Config)?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(3),
            }]),
        })
        .map_err(|_| Error::Config)?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|_| Error::Config)
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| Error::Config)?;
    let service = manager
        .open_service(
            platform::service_name(),
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|_| Error::Config)?;
    if service
        .query_status()
        .map_err(|_| Error::Config)?
        .current_state
        != ServiceState::Stopped
    {
        service.stop().map_err(|_| Error::Config)?;
    }
    service.delete().map_err(|_| Error::Config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_uses_virtual_account_and_installed_service_binary() {
        let info = service_info();
        assert_eq!(
            info.account_name,
            Some(OsString::from(r"NT SERVICE\KeyValetRelay"))
        );
        assert_eq!(info.name, "KeyValetRelay");
        assert_eq!(
            info.executable_path,
            Path::new(kv_platform::paths::INSTALL_DIR).join("bin/kv-relay-client.exe")
        );
        assert_eq!(info.launch_arguments, [OsString::from("--service")]);
        assert_eq!(
            info.dependencies,
            [ServiceDependency::Service("KeyValetHelper".into())]
        );
    }
}
