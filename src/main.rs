mod scan;

use iced::futures::Stream;
use iced::widget::{button, column, row, rule, scrollable, table, text};
use iced::{Element, Subscription, stream};

use scan::Device;

const WINDOW_TITLE: &str = "Net Probe";

#[derive(Default)]
struct NetProbe {
    devices: Vec<Device>,
    scanning: bool,
}

#[derive(Debug, Clone)]
enum Message {
    Refresh,
    HostFound(Device),
    ScanComplete,
}

impl NetProbe {
    fn update(&mut self, message: Message) {
        match message {
            Message::Refresh => {
                if !self.scanning {
                    self.devices.clear();
                    self.scanning = true;
                }
            }
            Message::HostFound(device) => {
                self.devices.push(device);
                self.devices.sort_by(|a, b| {
                    let a_parts: Vec<u8> = a.ip.split('.').filter_map(|p| p.parse().ok()).collect();
                    let b_parts: Vec<u8> = b.ip.split('.').filter_map(|p| p.parse().ok()).collect();
                    a_parts.cmp(&b_parts)
                });
            }
            Message::ScanComplete => {
                self.scanning = false;
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let refresh_label = if self.scanning {
            "Scanning..."
        } else {
            "Refresh"
        };

        let mut refresh_button = button(refresh_label);
        if !self.scanning {
            refresh_button = refresh_button.on_press(Message::Refresh);
        }

        let toolbar = row![
            refresh_button,
            text(format!("{} hosts found", self.devices.len()))
        ]
        .align_y(iced::Alignment::Center)
        .spacing(12)
        .padding(10);

        let device_table = table(
            vec![
                table::column("IP Address", |d: Device| text(d.ip)).width(iced::Length::Shrink),
                table::column("ICMP",       |d: Device| d.icmp.to_richtext()),
                table::column("Hostname",   |d: Device| text(d.hostname.unwrap_or_default())).width(iced::Length::Fill),
                table::column("MAC"  ,      |d: Device| text(d.mac.unwrap_or_default())),
                table::column("Vendor",     |d: Device| text(d.vendor.unwrap_or_default())),
                table::column("HTTP",       |d: Device| d.http.to_richtext()),
                table::column("HTTPS",      |d: Device| d.https.to_richtext()),
            ],
            self.devices.iter().cloned(),
        )
        .width(iced::Length::Fill);

        column![
            toolbar,
            rule::horizontal(1),
            scrollable(device_table)
                .width(iced::Length::Fill)
                .height(iced::Length::Fill)
        ]
        .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        if self.scanning {
            Subscription::run(scan_worker)
        } else {
            Subscription::none()
        }
    }
}

fn scan_worker() -> impl Stream<Item = Message> {
    stream::channel(64, async |mut output| {
        use iced::futures::sink::SinkExt;

        let Some(base) = scan::local_subnet_base() else {
            let _ = output.send(Message::ScanComplete).await;
            return;
        };

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Device>();

        let scan_task = tokio::spawn(async move {
            scan::scan_subnet(base, move |device| {
                let _ = tx.send(device);
            })
            .await;
        });

        while let Some(device) = rx.recv().await {
            if output.send(Message::HostFound(device)).await.is_err() {
                break;
            }
        }

        let _ = scan_task.await;
        let _ = output.send(Message::ScanComplete).await;
    })
}

fn main() -> iced::Result {
    iced::application(NetProbe::default, NetProbe::update, NetProbe::view)
        .subscription(NetProbe::subscription)
        .title(WINDOW_TITLE)
        .run()
}
