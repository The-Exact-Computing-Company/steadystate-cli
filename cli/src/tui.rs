use std::io::{self, Stdout};
use std::time::Duration;
use std::path::PathBuf;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

pub struct TuiApp {
    session_root: PathBuf,
    activity_log_path: PathBuf,
    sync_log_path: PathBuf,
    activities: Vec<String>,
    should_quit: bool,
    scroll: u16,
}

impl TuiApp {
    pub fn new() -> Result<Self> {
        let session_root = std::env::var("SESSION_ROOT").unwrap_or_else(|_| ".".to_string()).into();
        let activity_log_path = std::env::var("ACTIVITY_LOG").unwrap_or_else(|_| "activity-log".to_string()).into();
        let sync_log_path = std::env::var("SYNC_LOG").unwrap_or_else(|_| "sync-log".to_string()).into();

        Ok(Self {
            session_root,
            activity_log_path,
            sync_log_path,
            activities: Vec::new(),
            should_quit: false,
            scroll: 0,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        loop {
            self.refresh_data()?;
            terminal.draw(|f| self.ui(f))?;

            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') => self.should_quit = true,
                            KeyCode::Char('s') => {
                                // TODO: Trigger sync?
                                // For now, just let user know they can run 'steadystate sync' in another pane
                                // Or we can spawn it.
                            },
                            KeyCode::Up => {
                                if self.scroll > 0 {
                                    self.scroll -= 1;
                                }
                            },
                            KeyCode::Down => {
                                self.scroll += 1;
                            },
                            _ => {}
                        }
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }

    fn refresh_data(&mut self) -> Result<()> {
        // Read activity log (tail last 20 lines)
        if self.activity_log_path.exists() {
            let content = std::fs::read_to_string(&self.activity_log_path)?;
            self.activities = content.lines().rev().take(50).map(|s| s.to_string()).collect();
        }
        Ok(())
    }

    fn ui(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Body
                Constraint::Length(3), // Footer
            ])
            .split(f.size());

        // Header
        let title = Paragraph::new(format!("SteadyState Session: {}", self.session_root.display()))
            .block(Block::default().borders(Borders::ALL).title("Status"));
        f.render_widget(title, chunks[0]);

        // Body (Activity Log)
        let items: Vec<ListItem> = self.activities
            .iter()
            .map(|i| ListItem::new(i.as_str()))
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Activity Log"))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        
        f.render_widget(list, chunks[1]);

        // Footer
        let footer = Paragraph::new("Press 'q' to quit (detach)")
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, chunks[2]);
    }
}
