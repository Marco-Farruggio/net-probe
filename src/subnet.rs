use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::LazyLock;

pub static SUBNET_MASK: LazyLock<Option<Ipv4Addr>> = LazyLock::new(|| {
    let Some(local_ip) = *crate::net::LOCAL_IP else {
        return None;
    };
    find_subnet_mask(local_ip)
});

fn find_subnet_mask(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    // windows only
    let mut cmd = Command::new("ipconfig");
    cmd.arg("/all");

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let output = cmd.output().ok()?;

    let text = String::from_utf8_lossy(&output.stdout);

    let mut lines = text.lines();

    while let Some(line) = lines.next() {
        if !line.contains("IPv4 Address") {
            continue;
        }

        let ipv4 = line
            .split(':')
            .nth(1)?
            .trim()
            .trim_end_matches("(Preferred)")
            .trim()
            .parse::<Ipv4Addr>()
            .ok()?;

        if ipv4 != ip {
            continue;
        }

        // Find the next Subnet Mask line.
        for line in lines.by_ref() {
            if line.contains("Subnet Mask") {
                return line
                    .split(':')
                    .nth(1)?
                    .trim()
                    .parse::<Ipv4Addr>()
                    .ok();
            }

            // Don't accidentally cross into another adapter.
            if line.contains("adapter ") {
                break;
            }
        }
    }

    None
}