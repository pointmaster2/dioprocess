//! UI module for Process Monitor
//! Contains Dioxus components with Tailwind CSS

use dioxus::prelude::*;
use crate::process::{ProcessInfo, get_processes, kill_process};

/// Sort column options
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortColumn {
    Pid,
    Name,
    Memory,
    Threads,
}

/// Sort order options
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SortOrder {
    Ascending,
    Descending,
}

/// Process row component
#[component]
pub fn ProcessRow(
    process: ProcessInfo,
    is_selected: bool,
    max_memory: f64,
    on_select: EventHandler<u32>,
) -> Element {
    let memory_percent = if max_memory > 0.0 { 
        process.memory_mb / max_memory * 100.0 
    } else { 
        0.0 
    };
    let pid = process.pid;
    let exe_filename = process.exe_path.split('\\').last().unwrap_or(&process.exe_path).to_string();
    
    let row_class = if is_selected {
        "border-l-4 border-red-500 bg-red-500/20 hover:bg-red-500/30 cursor-pointer transition-colors"
    } else {
        "hover:bg-cyan-500/10 cursor-pointer transition-colors border-b border-white/5"
    };

    rsx! {
        tr { 
            key: "{process.pid}",
            class: "{row_class}",
            onclick: move |_| on_select.call(pid),
            td { class: "px-4 py-3 font-mono text-yellow-400 w-20", "{process.pid}" }
            td { class: "px-4 py-3 font-medium", "{process.name}" }
            td { class: "px-4 py-3 font-mono text-purple-400 w-20 text-center", "{process.thread_count}" }
            td { class: "px-4 py-3 w-44",
                div { class: "flex items-center gap-2",
                    div { class: "flex-1 h-2 bg-white/10 rounded overflow-hidden",
                        div { 
                            class: "h-full bg-gradient-to-r from-green-400 via-cyan-400 to-red-500 rounded transition-all duration-300",
                            style: "width: {memory_percent}%",
                        }
                    }
                    span { class: "font-mono text-green-400 text-xs min-w-[70px] text-right", "{process.memory_mb:.1} MB" }
                }
            }
            td { class: "px-4 py-3 text-xs text-gray-500 max-w-[200px] truncate hover:text-gray-400", title: "{process.exe_path}", "{exe_filename}" }
        }
    }
}

/// Main application component
#[component]
pub fn App() -> Element {
    let mut processes = use_signal(|| get_processes());
    let mut search_query = use_signal(|| String::new());
    let mut sort_column = use_signal(|| SortColumn::Memory);
    let mut sort_order = use_signal(|| SortOrder::Descending);
    let mut auto_refresh = use_signal(|| true);
    let mut selected_pid = use_signal(|| None::<u32>);
    let mut status_message = use_signal(|| String::new());

    // Auto-refresh every 3 seconds
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if *auto_refresh.read() {
                processes.set(get_processes());
            }
        }
    });

    // Find max memory for percentage calculation
    let max_memory = processes.read().iter().map(|p| p.memory_mb).fold(0.0_f64, |a, b| a.max(b));

    // Filter and sort processes
    let mut filtered_processes: Vec<ProcessInfo> = processes
        .read()
        .iter()
        .filter(|p| {
            let query = search_query.read().to_lowercase();
            if query.is_empty() {
                true
            } else {
                p.name.to_lowercase().contains(&query) 
                    || p.pid.to_string().contains(&query)
                    || p.exe_path.to_lowercase().contains(&query)
            }
        })
        .cloned()
        .collect();

    // Sort based on selected column
    filtered_processes.sort_by(|a, b| {
        let cmp = match *sort_column.read() {
            SortColumn::Pid => a.pid.cmp(&b.pid),
            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortColumn::Memory => a.memory_mb.partial_cmp(&b.memory_mb).unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Threads => a.thread_count.cmp(&b.thread_count),
        };
        match *sort_order.read() {
            SortOrder::Ascending => cmp,
            SortOrder::Descending => cmp.reverse(),
        }
    });

    let process_count = filtered_processes.len();
    let total_memory: f64 = filtered_processes.iter().map(|p| p.memory_mb).sum();

    // Get current sort state for display
    let current_sort_col = *sort_column.read();
    let current_sort_ord = *sort_order.read();

    // Get sort indicator
    let sort_indicator = |column: SortColumn| -> &'static str {
        if current_sort_col == column {
            match current_sort_ord {
                SortOrder::Ascending => " ▲",
                SortOrder::Descending => " ▼",
            }
        } else {
            ""
        }
    };

    rsx! {
        // Tailwind CDN
        script { src: "https://cdn.tailwindcss.com" }
        style { {CUSTOM_STYLES} }

        // Custom title bar for borderless window
        div { class: "flex justify-between items-center h-9 bg-gradient-to-r from-slate-950 to-slate-900 border-b border-cyan-500/20 select-none",
            div { 
                class: "flex-1 h-full flex items-center pl-3 cursor-move",
                onmousedown: move |_| {
                    let window = dioxus::desktop::window();
                    let _ = window.drag_window();
                },
                span { class: "text-sm font-medium text-cyan-400", "🖥️ Process Monitor" }
            }
            div { class: "flex h-full",
                button {
                    class: "w-12 h-full border-none bg-transparent text-gray-400 text-xs cursor-pointer transition-all hover:bg-white/10 hover:text-white",
                    onclick: move |_| {
                        let window = dioxus::desktop::window();
                        window.set_minimized(true);
                    },
                    "─"
                }
                button {
                    class: "w-12 h-full border-none bg-transparent text-gray-400 text-xs cursor-pointer transition-all hover:bg-white/10 hover:text-white",
                    onclick: move |_| {
                        let window = dioxus::desktop::window();
                        window.set_maximized(!window.is_maximized());
                    },
                    "□"
                }
                button {
                    class: "w-12 h-full border-none bg-transparent text-gray-400 text-xs cursor-pointer transition-all hover:bg-red-600 hover:text-white",
                    onclick: move |_| {
                        let window = dioxus::desktop::window();
                        window.close();
                    },
                    "✕"
                }
            }
        }

        div { class: "max-w-6xl mx-auto p-5 h-[calc(100vh-36px)] overflow-hidden flex flex-col",
            // Header
            div { class: "text-center mb-5 p-5 bg-white/5 rounded-xl backdrop-blur-sm",
                h1 { class: "text-3xl mb-2 text-cyan-400 font-bold", "🖥️ Windows Process Monitor" }
                div { class: "flex justify-center gap-8 text-sm text-gray-400",
                    span { "Processes: {process_count}" }
                    span { "Total Memory: {total_memory:.1} MB" }
                }
                if !status_message.read().is_empty() {
                    div { class: "mt-3 py-2 px-4 bg-cyan-500/20 rounded-md text-sm text-cyan-400 inline-block", "{status_message}" }
                }
            }

            // Controls
            div { class: "flex gap-4 mb-5 items-center flex-wrap",
                input {
                    class: "flex-1 min-w-[200px] py-3 px-4 border-none rounded-lg bg-white/10 text-white text-sm outline-none transition-colors focus:bg-white/15 placeholder:text-gray-500",
                    r#type: "text",
                    placeholder: "Search by name, PID, or path...",
                    value: "{search_query}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }
                
                label { class: "flex items-center gap-2 text-gray-400 text-sm cursor-pointer select-none",
                    input {
                        r#type: "checkbox",
                        class: "w-4 h-4 cursor-pointer accent-cyan-400",
                        checked: *auto_refresh.read(),
                        onchange: move |e| auto_refresh.set(e.checked()),
                    }
                    span { "Auto-refresh" }
                }

                button {
                    class: "py-3 px-6 border-none rounded-lg text-sm font-semibold cursor-pointer transition-all bg-gradient-to-br from-cyan-400 to-cyan-600 text-white hover:-translate-y-0.5 hover:shadow-lg hover:shadow-cyan-500/40 active:translate-y-0",
                    onclick: move |_| processes.set(get_processes()),
                    "🔄 Refresh"
                }

                button {
                    class: "py-3 px-6 border-none rounded-lg text-sm font-semibold cursor-pointer transition-all bg-gradient-to-br from-red-500 to-red-700 text-white hover:-translate-y-0.5 hover:shadow-lg hover:shadow-red-500/40 active:translate-y-0 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none",
                    disabled: selected_pid.read().is_none(),
                    onclick: move |_| {
                        let pid_to_kill = *selected_pid.read();
                        if let Some(pid) = pid_to_kill {
                            if kill_process(pid) {
                                status_message.set(format!("✓ Process {} terminated", pid));
                                processes.set(get_processes());
                                selected_pid.set(None);
                            } else {
                                status_message.set(format!("✗ Failed to terminate process {} (access denied?)", pid));
                            }
                            spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                status_message.set(String::new());
                            });
                        }
                    },
                    "☠️ Kill Process"
                }
            }

            // Process table
            div { class: "bg-white/5 rounded-xl flex-1 overflow-y-auto overflow-x-hidden min-h-0",
                table { class: "w-full border-collapse",
                    thead { class: "sticky top-0 bg-cyan-500/20 backdrop-blur-sm z-10",
                        tr {
                            th { 
                                class: "px-4 py-4 text-left font-semibold text-cyan-400 border-b-2 border-cyan-500/30 cursor-pointer select-none transition-colors hover:bg-cyan-500/30",
                                onclick: move |_| {
                                    if *sort_column.read() == SortColumn::Pid {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(SortColumn::Pid);
                                        sort_order.set(SortOrder::Descending);
                                    }
                                },
                                "PID{sort_indicator(SortColumn::Pid)}" 
                            }
                            th { 
                                class: "px-4 py-4 text-left font-semibold text-cyan-400 border-b-2 border-cyan-500/30 cursor-pointer select-none transition-colors hover:bg-cyan-500/30",
                                onclick: move |_| {
                                    if *sort_column.read() == SortColumn::Name {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(SortColumn::Name);
                                        sort_order.set(SortOrder::Descending);
                                    }
                                },
                                "Process Name{sort_indicator(SortColumn::Name)}" 
                            }
                            th { 
                                class: "px-4 py-4 text-left font-semibold text-cyan-400 border-b-2 border-cyan-500/30 cursor-pointer select-none transition-colors hover:bg-cyan-500/30",
                                onclick: move |_| {
                                    if *sort_column.read() == SortColumn::Threads {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(SortColumn::Threads);
                                        sort_order.set(SortOrder::Descending);
                                    }
                                },
                                "Threads{sort_indicator(SortColumn::Threads)}" 
                            }
                            th { 
                                class: "px-4 py-4 text-left font-semibold text-cyan-400 border-b-2 border-cyan-500/30 cursor-pointer select-none transition-colors hover:bg-cyan-500/30",
                                onclick: move |_| {
                                    if *sort_column.read() == SortColumn::Memory {
                                        let new_order = if *sort_order.read() == SortOrder::Ascending { SortOrder::Descending } else { SortOrder::Ascending };
                                        sort_order.set(new_order);
                                    } else {
                                        sort_column.set(SortColumn::Memory);
                                        sort_order.set(SortOrder::Descending);
                                    }
                                },
                                "Memory{sort_indicator(SortColumn::Memory)}" 
                            }
                            th { class: "px-4 py-4 text-left font-semibold text-cyan-400 border-b-2 border-cyan-500/30", "Path" }
                        }
                    }
                    tbody {
                        for process in filtered_processes {
                            ProcessRow { 
                                process: process.clone(),
                                is_selected: *selected_pid.read() == Some(process.pid),
                                max_memory: max_memory,
                                on_select: move |pid: u32| {
                                    let current = *selected_pid.read();
                                    if current == Some(pid) {
                                        selected_pid.set(None);
                                    } else {
                                        selected_pid.set(Some(pid));
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Minimal custom styles (only for things Tailwind can't handle easily)
pub const CUSTOM_STYLES: &str = r#"
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    html, body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        color: #eee;
        height: 100%;
        overflow: hidden;
    }

    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }

    ::-webkit-scrollbar-track {
        background: transparent;
    }

    ::-webkit-scrollbar-thumb {
        background: rgba(0, 212, 255, 0.3);
        border-radius: 3px;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 212, 255, 0.5);
    }
"#;
