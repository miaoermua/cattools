/* src/cli.rs */

#[derive(Debug, Default)]
pub struct Cli {
    pub update: bool,
    pub config: Option<String>,
}

impl Cli {
    pub fn parse() -> Self {
        let mut cli = Self::default();
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-u" | "--update" => cli.update = true,
                "--config" => {
                    if let Some(path) = args.next() {
                        cli.config = Some(path);
                    }
                }
                _ => {}
            }
        }

        cli
    }
}
