//! Mudra/Cyb's ANSI Shadow wordmark and restrained terminal help palette.
use clap::{
    ColorChoice, Command,
    builder::styling::{AnsiColor, Styles},
};
use std::{fmt::Write, io::IsTerminal};

const LOGO: [&str; 6] = [
    "██╗   ██╗ █████╗ ██╗   ██╗██╗     ████████╗",
    "██║   ██║██╔══██╗██║   ██║██║     ╚══██╔══╝",
    "██║   ██║███████║██║   ██║██║        ██║   ",
    "╚██╗ ██╔╝██╔══██║██║   ██║██║        ██║   ",
    " ╚████╔╝ ██║  ██║╚██████╔╝███████╗   ██║   ",
    "  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ",
];
const COLORS: [&str; 6] = ["31", "33", "32", "36", "34", "35"];

struct Theme {
    terminal: bool,
    color: bool,
}
impl Theme {
    fn detect() -> Self {
        let terminal = std::io::stdout().is_terminal()
            && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        Self {
            terminal,
            color: terminal && !no_color,
        }
    }
    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.into()
        }
    }
    fn heading(&self, out: &mut String, text: &str) {
        let _ = writeln!(out, "  {}", self.paint("90", text));
    }
    fn row(&self, out: &mut String, label: &str, description: &str) {
        let _ = writeln!(
            out,
            "    {}  {}",
            self.paint("1", &format!("{label:<18}")),
            self.paint("90", description)
        );
    }
}

pub fn command(command: Command) -> Command {
    let theme = Theme::detect();
    let mut command = style(command, &theme);
    command.build();
    let overview = overview(&command, &theme);
    command.override_help(overview)
}

fn style(command: Command, theme: &Theme) -> Command {
    let name = command.get_name();
    let title = if name == "vault" || name == "cyber-vault" {
        "vault".to_string()
    } else {
        format!("vault {name}")
    };
    let styles = Styles::styled()
        .header(AnsiColor::BrightBlack.on_default())
        .usage(AnsiColor::BrightBlack.on_default())
        .literal(AnsiColor::Cyan.on_default().bold())
        .placeholder(AnsiColor::Yellow.on_default())
        .valid(AnsiColor::Green.on_default())
        .error(AnsiColor::Red.on_default().bold());
    command
        .styles(styles)
        .color(if theme.color {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        })
        .before_help(format!("\n  {}", theme.paint("1;36", &title)))
        .help_template("{before-help}  {about}\n\n  usage\n    {usage}\n\n{all-args}")
        .mut_subcommands(|subcommand| style(subcommand, theme))
}

fn category(name: &str) -> &str {
    match name {
        "show" | "otp" | "recovery-code" | "derive-neuron" | "sign" => "use",
        "replica-add" | "sync" | "checkpoint" | "recover" => "recovery",
        _ => "custody",
    }
}

fn overview(command: &Command, theme: &Theme) -> String {
    let mut out = String::from("\n");
    if theme.terminal {
        for (row, color) in LOGO.iter().zip(COLORS) {
            let _ = writeln!(out, "  {}", theme.paint(color, row.trim_end()));
        }
        let _ = writeln!(out, "\n    your secrets survive your devices");
        let _ = writeln!(
            out,
            "    {}\n",
            theme.paint(
                "90",
                &format!("vault {} · soft3", env!("CARGO_PKG_VERSION"))
            )
        );
    } else {
        let _ = writeln!(
            out,
            "  vault {} — your secrets survive your devices\n",
            env!("CARGO_PKG_VERSION")
        );
    }

    for group in ["custody", "use", "recovery"] {
        theme.heading(&mut out, group);
        for subcommand in command.get_subcommands().filter(|c| {
            !c.is_hide_set() && c.get_name() != "help" && category(c.get_name()) == group
        }) {
            let description = subcommand
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            theme.row(&mut out, subcommand.get_name(), &description);
        }
        out.push('\n');
    }

    theme.heading(&mut out, "flags");
    for arg in command.get_arguments().filter(|a| !a.is_hide_set()) {
        let mut label = String::new();
        if let Some(short) = arg.get_short() {
            let _ = write!(label, "-{short}, ");
        }
        if let Some(long) = arg.get_long() {
            let _ = write!(label, "--{long}");
        }
        if arg.get_action().takes_values() {
            let name = arg
                .get_value_names()
                .and_then(|names| names.first())
                .map(ToString::to_string)
                .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
            let _ = write!(label, " <{name}>");
        }
        let description = arg.get_help().map(ToString::to_string).unwrap_or_default();
        theme.row(&mut out, &label, &description);
    }

    out.push('\n');
    theme.heading(&mut out, "start");
    for example in [
        "vault init --recovery-file /path/to/recovery.factor",
        "vault add spell --label main --scope neuron",
        "vault list",
    ] {
        let _ = writeln!(out, "    {}", theme.paint("32", example));
    }
    let _ = writeln!(
        out,
        "\n    {}",
        theme.paint("90", "vault <command> --help  ·  details and options")
    );
    out
}
