use anyhow::{Context, Result};
use crossterm::event::{self, KeyCode, KeyEventKind};
use cugparck_core::{
    init_setup, CompressedTable, CudaRuntime, Dx12, Event, Metal, OpenGl, RainbowTable,
    RainbowTableCtx, RainbowTableCtxBuilder, SimpleTable, SimpleTableHandle, Vulkan, WebGpu,
    WgpuRuntime, DEFAULT_FILTER_COUNT,
};
use human_repr::HumanDuration;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    symbols,
    text::Line,
    widgets::{Axis, Block, Chart, Dataset, Gauge, GraphType, LineGauge, List, Tabs, Widget},
    DefaultTerminal, Frame,
};
use std::{
    iter,
    time::{Duration, Instant},
};

use crate::{create_dir_to_store_tables, AvailableBackend, Generate};

struct TableStats {
    ctx: RainbowTableCtx,
    progress: f64,
    unique_chains: u64,
    mi_reference: Vec<(f64, f64)>,
    filtration_stats: Vec<(f64, f64)>,
    start_time: Option<Instant>,
    end_time: Option<Instant>,
}

impl TableStats {
    /// Registers a new filtration step in the stats.
    /// That is, a (chain_pos, unique_chains_count) pair.
    fn register_filtration_step(&mut self, chain_pos: u64, unique_chains_count: usize) {
        self.unique_chains = unique_chains_count as u64;

        // push the filtration step twice so it's correctly renderered as chunks and no
        // interpolation is done
        if let Some((_, last_unique_chains)) = self.filtration_stats.last() {
            self.filtration_stats
                .push((chain_pos as f64, *last_unique_chains));
        }

        self.filtration_stats
            .push((chain_pos as f64, unique_chains_count as f64));
    }
}

impl TableStats {
    fn render_overview(&self, area: Rect, buf: &mut Buffer) {
        let [progress, stats] =
            Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(area);

        LineGauge::default()
            .block(Block::bordered().title("Progress"))
            .filled_style(Style::new().blue().bold())
            .line_set(symbols::line::THICK)
            .ratio(self.progress)
            .render(progress, buf);

        let duration = match self.start_time {
            None => String::new(),
            Some(start) if start.elapsed() < Duration::from_secs(1) => String::new(),
            Some(start) => (self
                .end_time
                .unwrap_or_else(Instant::now)
                .duration_since(start))
            .as_secs()
            .human_duration()
            .to_string(),
        };

        List::new([
            format!("{:<30} {}", "Unique chains", self.unique_chains),
            format!("{:<30} {}", "Duration ", duration),
        ])
        .block(Block::bordered().title("Stats"))
        .style(Style::new().white())
        .highlight_style(Style::new().italic())
        .render(stats, buf);
    }

    fn render_filtration(&self, area: Rect, buf: &mut Buffer) {
        let expected_dataset = Dataset::default()
            .name("Expected number of unique chains")
            .marker(symbols::Marker::Braille)
            .style(Style::new().fg(Color::Red))
            .graph_type(GraphType::Line)
            .data(&self.mi_reference);

        let actual_dataset = Dataset::default()
            .name(format!(
                "Actual filtration ({} filters)",
                DEFAULT_FILTER_COUNT
            ))
            .marker(symbols::Marker::Braille)
            .style(Style::new().fg(Color::Blue))
            .graph_type(GraphType::Line)
            .data(&self.filtration_stats);

        Chart::new(vec![expected_dataset, actual_dataset])
            .block(
                Block::bordered()
                    .title_top(Line::from("Filtration Stats").cyan().bold().centered()),
            )
            .x_axis(
                Axis::default()
                    .title("Chain length")
                    .style(Style::default().gray())
                    .bounds([0.0, self.ctx.t as f64])
                    .labels(["0".bold(), self.ctx.t.to_string().bold()]),
            )
            .y_axis(
                Axis::default()
                    .title("Unique chains")
                    .style(Style::default().gray())
                    .bounds([0.0, self.ctx.m0 as f64])
                    .labels(["0".bold(), self.ctx.m0.to_string().bold()]),
            )
            .hidden_legend_constraints((Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)))
            .render(area, buf);
    }
}

impl Widget for &TableStats {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        let [overview, filtration] =
            Layout::vertical([Constraint::Length(7), Constraint::Fill(1)]).areas(area);

        self.render_overview(overview, buf);
        self.render_filtration(filtration, buf);
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
enum Tab {
    #[default]
    Dashboard,
    Table(u8),
}

struct GenerateWidget {
    args: Generate,
    current_tab: Tab,
    ctx_builder: RainbowTableCtxBuilder,
    table_stats: Vec<TableStats>,
    exit: bool,
}

impl GenerateWidget {
    pub fn new(ctx_builder: RainbowTableCtxBuilder, args: Generate) -> Result<Self> {
        Ok(Self {
            current_tab: Tab::Table(args.start_from),
            args,
            ctx_builder,
            table_stats: Vec::new(),
            exit: false,
        })
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        create_dir_to_store_tables(&self.args.dir)?;
        let ext = if self.args.compress { "rtcde" } else { "rt" };

        // create all table stats
        for i in self.args.start_from..self.args.table_count {
            let ctx = self.ctx_builder.clone().table_number(i).build()?;

            // precompute the theoritical number of unique chains
            const DATA_POINTS: u64 = 20;
            let mut mi_reference = Vec::new();
            for i in 0..DATA_POINTS {
                let chain_pos = ctx.t / DATA_POINTS * i;
                mi_reference.push((chain_pos as f64, ctx.mi(chain_pos) as f64));
            }

            self.table_stats.push(TableStats {
                mi_reference,
                progress: 0.,
                unique_chains: ctx.m0,
                ctx,
                filtration_stats: Vec::new(),
                start_time: None,
                end_time: None,
            });
        }

        // loop until all tables are generated
        'main: for i in 0..self.args.table_count {
            self.table_stats[i as usize].start_time = Some(Instant::now());
            let ctx = self.table_stats[i as usize].ctx.clone();

            let table_handle = match self.args.backend {
                AvailableBackend::Cuda => SimpleTable::new_with_events::<CudaRuntime>(ctx)?,
                _ => SimpleTable::new_with_events::<WgpuRuntime>(ctx)?,
            };

            // handle events while the table is being generated
            while !table_handle.handle.is_finished() {
                if self.exit {
                    break 'main;
                }

                terminal.draw(|frame| self.draw(frame))?;
                self.handle_user_events()?;
                self.handle_generation_events(&table_handle, i)?;
            }

            self.table_stats[i as usize].end_time = Some(Instant::now());

            let simple_table = table_handle.handle.join().unwrap()?;
            let table_path = self.args.dir.clone().join(format!("table_{i}.{ext}"));
            let disk_error = "Unable to store the generated rainbow table to the disk";
            if self.args.compress {
                simple_table
                    .into_rainbow_table::<CompressedTable>()
                    .store(&table_path)
                    .context(disk_error)?
            } else {
                simple_table.store(&table_path).context(disk_error)?;
            }

            // let pb = ProgressBar::new(10_000).with_style(
            //     ProgressStyle::default_bar()
            //         .template("{spinner:.green} {msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}]")
            //         .unwrap()
            //         .progress_chars("#>-"),
            // );
            // pb.enable_steady_tick(Duration::from_millis(100));

            // while let Some(event) = table_handle.recv() {
            //     match event {
            //         Event::Progress(progress) => pb.set_position((progress * 100.) as u64),
            //         Event::Batch {
            //             batch_number,
            //             batch_count,
            //             columns,
            //         } => pb.set_message(format!(
            //             "Running batch {batch_number}/{batch_count} of columns {columns:?}"
            //         )),
            //     }
            // }

            // pb.finish_with_message("Done");
        }

        // do not exit the TUI when the generation is finished
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_user_events()?;
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_generation_events(
        &mut self,
        table_handle: &SimpleTableHandle,
        current_table: u8,
    ) -> Result<()> {
        while let Ok(event) = table_handle.receiver.try_recv() {
            match event {
                Event::FiltrationStep {
                    col_start,
                    unique_chains,
                } => {
                    self.table_stats[current_table as usize]
                        .register_filtration_step(col_start, unique_chains);
                }

                Event::Progress(progress) => {
                    self.table_stats[current_table as usize].progress = progress;
                }

                _ => (),
            }
        }

        Ok(())
    }

    fn handle_user_events(&mut self) -> Result<()> {
        if !event::poll(Duration::from_millis(100))? {
            return Ok(());
        }

        let crossterm::event::Event::Key(key_event) = event::read()? else {
            return Ok(());
        };

        if key_event.kind != KeyEventKind::Press {
            return Ok(());
        }

        match key_event.code {
            KeyCode::Char('h') | KeyCode::Left => {
                self.current_tab = match self.current_tab {
                    Tab::Dashboard => Tab::Table(self.args.start_from + self.args.table_count - 1),
                    Tab::Table(i) if i == self.args.start_from => Tab::Dashboard,
                    Tab::Table(i) => Tab::Table(i - 1),
                }
            }
            KeyCode::Char('l') | KeyCode::Right => {
                self.current_tab = match self.current_tab {
                    Tab::Dashboard => Tab::Table(self.args.start_from),
                    Tab::Table(i) if i == self.args.start_from + self.args.table_count - 1 => {
                        Tab::Dashboard
                    }
                    Tab::Table(i) => Tab::Table(i + 1),
                }
            }
            KeyCode::Char('q') | KeyCode::Esc => self.exit = true,
            _ => {}
        }

        Ok(())
    }

    fn render_dashboard(&self, area: Rect, buf: &mut Buffer) {
        let [infos, progress] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(area);

        let ctx = self.ctx_builder.clone().build().unwrap();
        List::new([
            format!("{:<30} {}", "Hash function", ctx.hash_function),
            format!(
                "{:<30} {}",
                "Charset",
                String::from_utf8_lossy(&ctx.charset)
            ),
            format!("{:<30} {}", "Chain length (t)", ctx.t),
            format!("{:<30} {}", "Starting chains (m0)", ctx.m0),
            format!("{:<30} {}", "Search space size (n)", ctx.n),
            format!(
                "{:<30} {}-{}",
                "Tables to generate",
                self.args.start_from,
                self.args.start_from + self.args.table_count - 1
            ),
        ])
        .block(Block::bordered().title("Informations"))
        .style(Style::new().white())
        .highlight_style(Style::new().italic())
        .render(infos, buf);

        Gauge::default()
            .block(Block::bordered().title("Progress"))
            .gauge_style(Style::new().blue())
            .ratio(
                self.table_stats
                    .iter()
                    .map(|table| table.progress)
                    .sum::<f64>()
                    / 4.,
            )
            .render(progress, buf);
    }
}

impl Widget for &GenerateWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let vertical = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ]);
        let [header, inner, footer] = vertical.areas(area);
        let horizontal = Layout::horizontal([Constraint::Min(0), Constraint::Length(20)]);
        let [tabs, title] = horizontal.areas(header);

        let tab_names = iter::once("Dashboard".to_owned()).chain(
            (self.args.start_from..self.args.start_from + self.args.table_count)
                .map(|i| format!("Table {i}")),
        );

        Tabs::new(tab_names)
            .select(match self.current_tab {
                Tab::Dashboard => 0,
                Tab::Table(i) => i as usize - self.args.start_from as usize + 1,
            })
            .padding("", "")
            .divider(" ")
            .render(tabs, buf);

        Line::from(vec!["Cugparck".into()]).render(title, buf);

        match self.current_tab {
            Tab::Dashboard => {
                self.render_dashboard(inner, buf);
            }
            Tab::Table(i) => {
                let table = &self.table_stats[i as usize - self.args.start_from as usize];
                table.render(inner, buf);
            }
        }

        Line::from(vec![
            " Page Left ".into(),
            "<Left>".blue().bold(),
            " Page Right ".into(),
            "<Right>".blue().bold(),
            " Quit ".into(),
            "<Q> ".blue().bold(),
        ])
        .render(footer, buf);
    }
}

pub fn generate(args: Generate) -> Result<()> {
    let ctx_builder = RainbowTableCtxBuilder::new()
        .hash(args.hash_function.into())
        .alpha(args.alpha)
        .startpoints(args.startpoints)
        .chain_length(args.chain_length)
        .charset(args.charset.as_bytes())
        .max_password_length(args.max_password_length);

    match args.backend {
        AvailableBackend::Dx12 => {
            init_setup::<Dx12>(&Default::default(), Default::default());
        }
        AvailableBackend::Metal => {
            init_setup::<Metal>(&Default::default(), Default::default());
        }
        AvailableBackend::OpenGl => {
            init_setup::<OpenGl>(&Default::default(), Default::default());
        }
        AvailableBackend::Vulkan => {
            init_setup::<Vulkan>(&Default::default(), Default::default());
        }
        AvailableBackend::WebGpu => {
            init_setup::<WebGpu>(&Default::default(), Default::default());
        }
        _ => (),
    }

    let mut terminal = ratatui::init();
    GenerateWidget::new(ctx_builder, args)?.run(&mut terminal)?;
    ratatui::restore();

    Ok(())
}
