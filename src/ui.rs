//! UI module for Process Monitor
//! Contains Dioxus components and styles

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
    
    rsx! {
        tr { 
            key: "{process.pid}",
            class: if is_selected { "selected" } else { "" },
            onclick: move |_| on_select.call(pid),
            td { class: "pid", "{process.pid}" }
            td { class: "name", "{process.name}" }
            td { class: "threads", "{process.thread_count}" }
            td { class: "memory",
                div { class: "memory-cell",
                    div { 
                        class: "memory-bar",
                        div { 
                            class: "memory-bar-fill",
                            style: "width: {memory_percent}%",
                        }
                    }
                    span { class: "memory-text", "{process.memory_mb:.1} MB" }
                }
            }
            td { class: "path", title: "{process.exe_path}", "{exe_filename}" }
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
        style { {STYLES} }

        // Custom title bar for borderless window
        div { class: "title-bar",
            div { 
                class: "title-bar-drag",
                onmousedown: move |_| {
                    let window = dioxus::desktop::window();
                    let _ = window.drag_window();
                },
                span { class: "title-text", "🖥️ Process Monitor" }
            }
            div { class: "title-bar-buttons",
                button {
                    class: "title-btn minimize-btn",
                    onclick: move |_| {
                        let window = dioxus::desktop::window();
                        window.set_minimized(true);
                    },
                    "─"
                }
                button {
                    class: "title-btn maximize-btn",
                    onclick: move |_| {
                        let window = dioxus::desktop::window();
                        window.set_maximized(!window.is_maximized());
                    },
                    "□"
                }
                button {
                    class: "title-btn close-btn",
                    onclick: move |_| {
                        let window = dioxus::desktop::window();
                        window.close();
                    },
                    "✕"
                }
            }
        }

        div { class: "container",
            // Header
            div { class: "header",
                h1 { "🖥️ Windows Process Monitor" }
                div { class: "stats",
                    span { "Processes: {process_count}" }
                    span { "Total Memory: {total_memory:.1} MB" }
                }
                if !status_message.read().is_empty() {
                    div { class: "status-message", "{status_message}" }
                }
            }

            // Controls
            div { class: "controls",
                input {
                    class: "search-input",
                    r#type: "text",
                    placeholder: "Search by name, PID, or path...",
                    value: "{search_query}",
                    oninput: move |e| search_query.set(e.value().clone()),
                }
                
                label { class: "auto-refresh-toggle",
                    input {
                        r#type: "checkbox",
                        checked: *auto_refresh.read(),
                        onchange: move |e| auto_refresh.set(e.checked()),
                    }
                    span { "Auto-refresh" }
                }

                button {
                    class: "refresh-btn",
                    onclick: move |_| processes.set(get_processes()),
                    "🔄 Refresh"
                }

                button {
                    class: "kill-btn",
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
                            // Clear message after 3 seconds
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
            div { class: "table-container",
                table { class: "process-table",
                    thead {
                        tr {
                            th { 
                                class: "sortable",
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
                                class: "sortable",
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
                                class: "sortable",
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
                                class: "sortable",
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
                            th { "Path" }
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

/// CSS Styles
pub const STYLES: &str = r#"
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

    /* Hide scrollbars globally but allow scrolling where needed */
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

    /* Custom Title Bar */
    .title-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        height: 36px;
        background: linear-gradient(135deg, #0d0d1a 0%, #1a1a2e 100%);
        border-bottom: 1px solid rgba(0, 212, 255, 0.2);
        user-select: none;
    }

    .title-bar-drag {
        flex: 1;
        height: 100%;
        display: flex;
        align-items: center;
        padding-left: 12px;
        cursor: move;
    }

    .title-text {
        font-size: 13px;
        font-weight: 500;
        color: #00d4ff;
    }

    .title-bar-buttons {
        display: flex;
        height: 100%;
    }

    .title-btn {
        width: 46px;
        height: 100%;
        border: none;
        background: transparent;
        color: #aaa;
        font-size: 12px;
        cursor: pointer;
        transition: background 0.15s, color 0.15s;
    }

    .title-btn:hover {
        background: rgba(255, 255, 255, 0.1);
        color: #fff;
    }

    .close-btn:hover {
        background: #e81123;
        color: #fff;
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
        height: calc(100vh - 36px);
        overflow: hidden;
        display: flex;
        flex-direction: column;
    }

    .header {
        text-align: center;
        margin-bottom: 20px;
        padding: 20px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        backdrop-filter: blur(10px);
    }

    .header h1 {
        font-size: 28px;
        margin-bottom: 10px;
        color: #00d4ff;
    }

    .stats {
        display: flex;
        justify-content: center;
        gap: 30px;
        font-size: 14px;
        color: #aaa;
    }

    .status-message {
        margin-top: 10px;
        padding: 8px 16px;
        background: rgba(0, 212, 255, 0.2);
        border-radius: 6px;
        font-size: 13px;
        color: #00d4ff;
    }

    .controls {
        display: flex;
        gap: 15px;
        margin-bottom: 20px;
        align-items: center;
        flex-wrap: wrap;
    }

    .search-input {
        flex: 1;
        min-width: 200px;
        padding: 12px 16px;
        border: none;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.1);
        color: #fff;
        font-size: 14px;
        outline: none;
        transition: background 0.3s;
    }

    .search-input:focus {
        background: rgba(255, 255, 255, 0.15);
    }

    .search-input::placeholder {
        color: #888;
    }

    .auto-refresh-toggle {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #aaa;
        font-size: 14px;
        cursor: pointer;
        user-select: none;
    }

    .auto-refresh-toggle input {
        width: 18px;
        height: 18px;
        cursor: pointer;
        accent-color: #00d4ff;
    }

    .refresh-btn, .kill-btn {
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: transform 0.2s, box-shadow 0.2s, opacity 0.2s;
    }

    .refresh-btn {
        background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
        color: #fff;
    }

    .refresh-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
    }

    .kill-btn {
        background: linear-gradient(135deg, #ff4757 0%, #cc0000 100%);
        color: #fff;
    }

    .kill-btn:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 5px 20px rgba(255, 71, 87, 0.4);
    }

    .kill-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
    }

    .refresh-btn:active, .kill-btn:active:not(:disabled) {
        transform: translateY(0);
    }

    .table-container {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        flex: 1;
        overflow-y: auto;
        overflow-x: hidden;
        min-height: 0;
    }

    .process-table {
        width: 100%;
        border-collapse: collapse;
    }

    .process-table thead {
        position: sticky;
        top: 0;
        background: rgba(0, 212, 255, 0.2);
        backdrop-filter: blur(10px);
        z-index: 10;
    }

    .process-table th {
        padding: 15px;
        text-align: left;
        font-weight: 600;
        color: #00d4ff;
        border-bottom: 2px solid rgba(0, 212, 255, 0.3);
    }

    .process-table th.sortable {
        cursor: pointer;
        user-select: none;
        transition: background 0.2s;
    }

    .process-table th.sortable:hover {
        background: rgba(0, 212, 255, 0.3);
    }

    .process-table td {
        padding: 12px 15px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .process-table tbody tr {
        transition: background 0.2s;
        cursor: pointer;
    }

    .process-table tbody tr:hover {
        background: rgba(0, 212, 255, 0.1);
    }

    .process-table tbody tr.selected {
        background: rgba(255, 71, 87, 0.2);
        border-left: 3px solid #ff4757;
    }

    .pid {
        font-family: 'Consolas', monospace;
        color: #ffd700;
        width: 80px;
    }

    .name {
        font-weight: 500;
        min-width: 150px;
    }

    .threads {
        font-family: 'Consolas', monospace;
        color: #a78bfa;
        width: 80px;
        text-align: center;
    }

    .memory {
        width: 180px;
    }

    .memory-cell {
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .memory-bar {
        flex: 1;
        height: 8px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 4px;
        overflow: hidden;
    }

    .memory-bar-fill {
        height: 100%;
        background: linear-gradient(90deg, #00ff88 0%, #00d4ff 50%, #ff4757 100%);
        border-radius: 4px;
        transition: width 0.3s ease;
    }

    .memory-text {
        font-family: 'Consolas', monospace;
        color: #00ff88;
        font-size: 12px;
        min-width: 70px;
        text-align: right;
    }

    .path {
        font-size: 12px;
        color: #888;
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .path:hover {
        color: #aaa;
    }
"#;
