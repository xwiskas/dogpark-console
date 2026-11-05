#!/usr/bin/env python3
"""DOGPARK Console — Tkinter entry point.

Launch with `python3 app.py` (Kali) or `python app.py` (Windows dev, tools are stubbed).
Importing this module must not touch the network; the LLM client only talks to localhost
and only when the user clicks "Explain output" / "What next?" / sends a chat message.
"""

from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from types import SimpleNamespace

from dogpark import custom, evidence, report, tools
from dogpark.llm import LLMClient
from dogpark.runner import Runner
from dogpark.scope import Scope

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

PHASE_CHOICES = [
    (-1, "All phases"),
    (0, "0 Pre-engagement"),
    (1, "1-2 Subscreen"),
    (3, "3-5 DMZ"),
    (6, "6-7 LAN"),
]

# ---------------------------------------------------------------------------
# Dark theme palette — clam base theme, no external deps. Kept as module-level
# constants so every widget builder can reference the same colors.
# ---------------------------------------------------------------------------
PALETTE = {
    "bg": "#1e1f2b",         # darkest — header strip
    "panel": "#262838",      # app background / panes
    "panel_alt": "#2d2f42",  # inputs, tree, cards
    "text": "#e6e6ef",
    "muted": "#9699b0",
    "accent": "#5bc0be",
    "accent_dark": "#3a8f8d",
    "red": "#e2566b",
    "red_dark": "#2a0b10",
    "green": "#4fd480",
    "green_dark": "#113821",
    "border": "#3a3c52",
}

UI_FONT = ("Segoe UI", 10)
UI_FONT_BOLD = ("Segoe UI", 10, "bold")
HEADER_FONT = ("Segoe UI", 14, "bold")
MONO_FONT = ("Consolas", 10)


def load_config() -> dict:
    """Read config.json from disk. No network calls — local file only."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


class DogparkApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DOGPARK Console")
        self.geometry("1320x780")
        self.minsize(980, 620)

        self.config_data = load_config()
        self.scope = Scope.from_config(self.config_data)
        self.output_dir = os.path.expanduser(self.config_data.get("output_dir", "~/dogpark"))
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        self.runner = Runner(self.output_dir)
        self.llm = LLMClient.from_config(self.config_data)
        self.findings = evidence.FindingsStore(self.output_dir)

        self.current_phase = tk.IntVar(value=-1)  # default to the "All phases" view
        self.stealth_mode = tk.BooleanVar(value=True)  # hide 'loud' commands by default
        self.day = tk.IntVar(value=1)
        self.target_var = tk.StringVar()
        self.scope_badge_text = tk.StringVar(value="enter a target")
        self.selected_action_id: str | None = None
        self.input_vars: dict[str, tk.StringVar] = {}
        self.command_var = tk.StringVar()

        # User- and AI-added commands (loaded from the JSON store; same scope/run rules apply).
        self.custom_path = custom.default_path()
        self.custom_actions: tuple = custom.load_custom_actions(self.custom_path)

        # AI chat panel state.
        self.chat_history: list[dict] = []
        self._chat_placeholder_seq = 0
        self._console_placeholder_seq = 0

        self._build_layout()
        self._refresh_tree()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def _apply_theme(self):
        p = PALETTE
        self.configure(background=p["panel"])
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            ".",
            background=p["panel"],
            foreground=p["text"],
            font=UI_FONT,
            fieldbackground=p["panel_alt"],
            bordercolor=p["border"],
            lightcolor=p["panel_alt"],
            darkcolor=p["panel_alt"],
            troughcolor=p["panel_alt"],
        )
        style.configure("TFrame", background=p["panel"])
        style.configure("TLabel", background=p["panel"], foreground=p["text"])
        style.configure("TButton", background=p["panel_alt"], foreground=p["text"], padding=6, relief="flat")
        style.map(
            "TButton",
            background=[("active", p["accent_dark"]), ("disabled", p["panel"])],
            foreground=[("disabled", p["muted"])],
        )
        style.configure("TCheckbutton", background=p["panel"], foreground=p["text"])
        style.map("TCheckbutton", background=[("active", p["panel"])])
        style.configure("TEntry", fieldbackground=p["panel_alt"], foreground=p["text"], insertcolor=p["text"])
        style.configure(
            "Mono.TEntry", font=MONO_FONT, fieldbackground=p["panel_alt"], foreground=p["text"],
            insertcolor=p["text"],
        )
        style.configure(
            "TCombobox",
            fieldbackground=p["panel_alt"],
            background=p["panel_alt"],
            foreground=p["text"],
            arrowcolor=p["text"],
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", p["panel_alt"])],
            foreground=[("readonly", p["text"])],
        )
        style.configure(
            "Treeview",
            background=p["panel_alt"],
            fieldbackground=p["panel_alt"],
            foreground=p["text"],
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", p["accent_dark"])], foreground=[("selected", p["text"])])
        style.configure("Treeview.Heading", background=p["panel"], foreground=p["text"])
        style.configure("TPanedwindow", background=p["panel"])
        style.configure("TNotebook", background=p["panel"], borderwidth=0)
        style.configure("TNotebook.Tab", background=p["panel_alt"], foreground=p["text"], padding=(12, 5))
        style.map("TNotebook.Tab", background=[("selected", p["accent_dark"])])
        style.configure("TSpinbox", fieldbackground=p["panel_alt"], foreground=p["text"], arrowcolor=p["text"])

        style.configure("Header.TFrame", background=p["bg"])
        style.configure("Header.TLabel", background=p["bg"], foreground=p["text"], font=HEADER_FONT)
        style.configure("Sub.TLabel", background=p["bg"], foreground=p["muted"], font=UI_FONT)

        style.configure("PillGreen.TLabel", background=p["green"], foreground=p["green_dark"], padding=(10, 3), font=UI_FONT_BOLD)
        style.configure("PillRed.TLabel", background=p["red"], foreground=p["red_dark"], padding=(10, 3), font=UI_FONT_BOLD)
        style.configure("PillGray.TLabel", background=p["panel_alt"], foreground=p["muted"], padding=(10, 3), font=UI_FONT_BOLD)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_layout(self):
        self._apply_theme()
        self._build_header()
        self._build_top_bar()

        self.main_paned = ttk.PanedWindow(self, orient="horizontal")
        self.main_paned.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        left = ttk.Frame(self.main_paned)
        self.main_paned.add(left, weight=1)
        self._build_tree(left)

        center = ttk.Frame(self.main_paned)
        self.main_paned.add(center, weight=3)
        self._build_center(center)

        right = ttk.Frame(self.main_paned)
        self.main_paned.add(right, weight=2)
        self._build_chat(right)

    def _build_header(self):
        header = ttk.Frame(self, style="Header.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="DOGPARK Console", style="Header.TLabel").pack(side="left", padx=14, pady=10)
        self.header_status_var = tk.StringVar()
        ttk.Label(header, textvariable=self.header_status_var, style="Sub.TLabel").pack(side="right", padx=14)
        self._update_header_status()

    def _update_header_status(self):
        phase_label = dict(PHASE_CHOICES).get(self.current_phase.get(), str(self.current_phase.get()))
        self.header_status_var.set(f"Phase: {phase_label}    •    Day {self.day.get()}")

    def _build_top_bar(self):
        bar = ttk.Frame(self, padding=(8, 8))
        bar.pack(fill="x", padx=6, pady=6)

        ttk.Label(bar, text="Target:").pack(side="left")
        target_entry = ttk.Entry(bar, textvariable=self.target_var, width=24)
        target_entry.pack(side="left", padx=(2, 8))
        target_entry.bind("<KeyRelease>", lambda e: self._on_target_changed())

        self.scope_badge = ttk.Label(bar, textvariable=self.scope_badge_text, style="PillGray.TLabel")
        self.scope_badge.pack(side="left", padx=(0, 16))

        ttk.Label(bar, text="Phase:").pack(side="left")
        phase_box = ttk.Combobox(
            bar,
            values=[label for _, label in PHASE_CHOICES],
            state="readonly",
            width=16,
        )
        phase_box.current(0)
        phase_box.pack(side="left", padx=(2, 16))
        phase_box.bind("<<ComboboxSelected>>", lambda e: self._on_phase_changed(phase_box.current()))

        ttk.Checkbutton(
            bar,
            text="Stealth mode (hide loud)",
            variable=self.stealth_mode,
            command=self._refresh_tree,
        ).pack(side="left", padx=(0, 16))

        ttk.Label(bar, text=f"Output: {self.output_dir}").pack(side="left", padx=(0, 16))

        ttk.Label(bar, text="Day:").pack(side="left")
        ttk.Spinbox(bar, from_=1, to=99, textvariable=self.day, width=4).pack(side="left")
        self.day.trace_add("write", lambda *_: self._update_header_status())

    def _build_tree(self, parent):
        ttk.Label(parent, text="Tools (current phase)").pack(anchor="w", padx=8, pady=(8, 4))
        self.tree = ttk.Treeview(parent, show="tree")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.tag_configure("risk_loud", foreground=PALETTE["red"])
        self.tree.tag_configure("risk_quiet", foreground=PALETTE["accent"])

    def _build_center(self, parent):
        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True)

        builder = ttk.Frame(paned, padding=(8, 8))
        paned.add(builder, weight=2)
        self._build_builder(builder)

        console_frame = ttk.Frame(paned, padding=(8, 4))
        paned.add(console_frame, weight=1)
        self._build_console(console_frame)

    def _build_builder(self, center):
        self.description_label = ttk.Label(center, text="Select an action from the tree.", wraplength=650, justify="left")
        self.description_label.pack(anchor="w", pady=(0, 6))

        self.inputs_frame = ttk.Frame(center)
        self.inputs_frame.pack(fill="x", pady=(0, 6))

        ttk.Label(center, text="Command (editable — review before running):").pack(anchor="w")
        self.command_entry = ttk.Entry(center, textvariable=self.command_var, style="Mono.TEntry")
        self.command_entry.pack(fill="x", pady=(0, 6))

        button_row = ttk.Frame(center)
        button_row.pack(fill="x", pady=(0, 6))

        self.run_button = ttk.Button(button_row, text="Run", command=self._on_run, state="disabled")
        self.run_button.pack(side="left", padx=(0, 4))
        ttk.Button(button_row, text="Stop", command=self._on_stop).pack(side="left", padx=4)
        ttk.Button(button_row, text="Explain output", command=self._on_explain).pack(side="left", padx=4)
        ttk.Button(button_row, text="What next?", command=self._on_suggest).pack(side="left", padx=4)
        ttk.Button(button_row, text="Add finding", command=self._on_add_finding).pack(side="left", padx=4)
        ttk.Button(button_row, text="Add command", command=self._on_add_command).pack(side="left", padx=4)
        ttk.Button(button_row, text="Reload custom", command=self._on_reload_custom).pack(side="left", padx=4)
        ttk.Button(button_row, text="Generate report", command=self._on_generate_report).pack(side="left", padx=4)

    def _build_console(self, console_frame):
        ttk.Label(console_frame, text="Output console:").pack(anchor="w")
        self.console = scrolledtext.ScrolledText(
            console_frame,
            height=10,
            font=MONO_FONT,
            background=PALETTE["bg"],
            foreground=PALETTE["text"],
            insertbackground=PALETTE["text"],
            borderwidth=0,
            highlightthickness=0,
        )
        self.console.pack(fill="both", expand=True)

        ttk.Button(console_frame, text="Save copy", command=self._on_save_console).pack(anchor="e", pady=4)

    def _build_chat(self, parent):
        ttk.Label(parent, text="AI recon advisor (on-box, localhost only)", font=UI_FONT_BOLD).pack(
            anchor="w", padx=8, pady=(8, 4)
        )

        self.chat_view = scrolledtext.ScrolledText(
            parent,
            wrap="word",
            state="disabled",
            font=MONO_FONT,
            background=PALETTE["bg"],
            foreground=PALETTE["text"],
            insertbackground=PALETTE["text"],
            borderwidth=0,
            highlightthickness=0,
        )
        self.chat_view.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.chat_view.tag_configure("user", foreground=PALETTE["accent"], font=(MONO_FONT[0], MONO_FONT[1], "bold"))
        self.chat_view.tag_configure("ai", foreground=PALETTE["text"])
        self.chat_view.tag_configure("meta", foreground=PALETTE["muted"], font=(MONO_FONT[0], 9, "italic"))

        quick_row = ttk.Frame(parent)
        quick_row.pack(fill="x", padx=8)
        ttk.Button(quick_row, text="Stealthy recon plan", command=self._on_chat_recon_plan).pack(
            side="left", fill="x", expand=True
        )

        input_row = ttk.Frame(parent)
        input_row.pack(fill="x", padx=8, pady=8)
        self.chat_input = tk.Text(
            input_row,
            height=3,
            font=UI_FONT,
            background=PALETTE["panel_alt"],
            foreground=PALETTE["text"],
            insertbackground=PALETTE["text"],
            wrap="word",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=PALETTE["border"],
        )
        self.chat_input.pack(side="left", fill="both", expand=True)
        self.chat_input.bind("<Control-Return>", self._on_chat_send_event)
        ttk.Button(input_row, text="Send\n(Ctrl+Enter)", command=self._on_chat_send).pack(
            side="left", padx=(6, 0), fill="y"
        )

        self._append_chat(
            "ai",
            "Ask me which recon command to run first — I'll prioritize staying quiet. Try "
            "'Stealthy recon plan', or type your own question below.",
        )

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    def _on_target_changed(self):
        target = self.target_var.get().strip()
        if not target:
            self.scope_badge_text.set("enter a target")
            self.scope_badge.configure(style="PillGray.TLabel")
            self.run_button.configure(state="disabled")
            return
        result = self.scope.check(target)
        if result.ok:
            self.scope_badge_text.set(f"IN SCOPE  {result.ip}")
            self.scope_badge.configure(style="PillGreen.TLabel")
        else:
            self.scope_badge_text.set(f"REFUSED: {result.reason}")
            self.scope_badge.configure(style="PillRed.TLabel")
        self._update_run_button_state()
        self._update_command_preview()

    def _update_run_button_state(self):
        target = self.target_var.get().strip()
        scope_ok = bool(target) and self.scope.check(target).ok
        has_action = self.selected_action_id is not None
        self.run_button.configure(state="normal" if (scope_ok and has_action) else "disabled")

    # ------------------------------------------------------------------
    # Tree / phase
    # ------------------------------------------------------------------
    def _on_phase_changed(self, index: int):
        phase, _ = PHASE_CHOICES[index]
        self.current_phase.set(phase)
        self._refresh_tree()
        self._update_header_status()

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        phase = self.current_phase.get()
        # phase == -1 is the "All phases" view: show every tool and every action so nothing is
        # ever hidden from the Run button. Otherwise scope the tree to the selected phase.
        if phase == -1:
            relevant_tools = tools.all_tools()
        else:
            relevant_tools = tools.tools_for_phase(phase) or tools.all_tools()
        stealth = self.stealth_mode.get()

        def visible(action) -> bool:
            # Stealth mode hides 'loud' commands so one can't be fired by accident.
            return not (stealth and action.risk == "loud")

        # Host discovery pinned to the top, per spec.
        ordered = sorted(relevant_tools, key=lambda t: 0 if t.category == "discovery" else 1)
        for tool in ordered:
            shown = [a for a in tool.actions if visible(a)]
            if not shown:
                continue
            tool_node = self.tree.insert("", "end", text=tool.name, values=(tool.name,), open=False)
            for action in shown:
                label = action.label + ("  ·loud" if action.risk == "loud" else "")
                self.tree.insert(
                    tool_node, "end", text=label, values=(action.id,), tags=(f"risk_{action.risk}",)
                )

        # User/AI-added commands under their own clearly labelled group.
        custom_shown = [a for a in self.custom_actions if visible(a)]
        if custom_shown:
            node = self.tree.insert("", "end", text=custom.CUSTOM_GROUP, values=(custom.CUSTOM_GROUP,), open=True)
            for action in custom_shown:
                label = action.label + ("  ·loud" if action.risk == "loud" else "")
                self.tree.insert(
                    node, "end", text=label, values=(action.id,), tags=(f"risk_{action.risk}",)
                )

    def _on_tree_select(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        values = self.tree.item(item, "values")
        if not values:
            return
        action_id = values[0]
        found = self._lookup_action(action_id)
        if not found:
            return  # a tool-group node, not an action
        tool, action = found
        self.selected_action_id = action.id
        self._render_action(tool, action)
        self._update_run_button_state()

    def _lookup_action(self, action_id):
        """Find (tool-like, action) across the built-in catalog and the custom/AI store."""
        found = tools.find_action(action_id)
        if found:
            return found
        for action in self.custom_actions:
            if action.id == action_id:
                return SimpleNamespace(name=custom.CUSTOM_GROUP), action
        return None

    # ------------------------------------------------------------------
    # Action / command building
    # ------------------------------------------------------------------
    def _render_action(self, tool, action):
        risk_note = f"  [risk: {action.risk}]"
        notes = f"\nNote: {action.notes}" if action.notes else ""
        self.description_label.configure(
            text=f"{tool.name} — {action.label}{risk_note}\n{action.description}{notes}"
        )

        for widget in self.inputs_frame.winfo_children():
            widget.destroy()
        self.input_vars = {}

        defaults = {
            "output": self.output_dir,
            "wordlist": self.config_data.get("wordlists", {}).get("dirb", ""),
        }
        for need in action.needs:
            row = ttk.Frame(self.inputs_frame)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=f"{need}:", width=12).pack(side="left")
            var = tk.StringVar(value=defaults.get(need, "" if need != "target" else self.target_var.get()))
            entry = ttk.Entry(row, textvariable=var)
            entry.pack(side="left", fill="x", expand=True)
            var.trace_add("write", lambda *_, n=need: self._update_command_preview())
            self.input_vars[need] = var

        self._update_command_preview()

    def _current_action(self):
        if not self.selected_action_id:
            return None
        found = self._lookup_action(self.selected_action_id)
        return found[1] if found else None

    def _gather_values(self) -> dict:
        values = {name: var.get() for name, var in self.input_vars.items()}
        values.setdefault("target", self.target_var.get().strip())
        return values

    def _update_command_preview(self):
        action = self._current_action()
        if not action:
            return
        values = self._gather_values()
        self.command_var.set(action.build_command(values))

    # ------------------------------------------------------------------
    # Console helpers (placeholder text for in-flight async calls)
    # ------------------------------------------------------------------
    def _append_console(self, line: str):
        self.console.insert("end", line + "\n")
        self.console.see("end")

    def _replace_console_placeholder(self, placeholder: str, final: str):
        """Swap a 'thinking…' placeholder line for the real result once an LLM call returns,
        without disturbing anything the user typed/ran in the meantime."""
        content = self.console.get("1.0", "end")
        idx = content.rfind(placeholder)
        if idx == -1:
            self._append_console(final)
            return
        start = f"1.0+{idx}c"
        end = f"1.0+{idx + len(placeholder)}c"
        self.console.delete(start, end)
        self.console.insert(start, final)
        self.console.see("end")

    # ------------------------------------------------------------------
    # Buttons
    # ------------------------------------------------------------------
    def _on_run(self):
        target = self.target_var.get().strip()
        result = self.scope.check(target)
        if not result.ok:
            messagebox.showerror("Scope check failed", result.reason)
            return
        action = self._current_action()
        if not action:
            return
        command = self.command_var.get()
        self._append_console(f"$ {command}")

        def on_line(line):
            self.after(0, self._append_console, line)

        def on_done(run_result):
            self.after(0, self._append_console, f"[done] exit={run_result.exit_code} log={run_result.log_path}")

        self.runner.run(
            command=command,
            target=target,
            action_id=action.id,
            day=self.day.get(),
            on_line=on_line,
            on_done=on_done,
        )

    def _on_stop(self):
        self.runner.stop()
        self._append_console("[stop requested]")

    def _on_explain(self):
        """Ask the local LLM to explain the console output. Threaded so the GUI never blocks
        waiting on the (localhost-only) network call; a 'thinking…' placeholder is shown
        immediately and swapped for the real answer via self.after()."""
        text = self.console.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Explain output", "No console output to explain yet.")
            return
        self._console_placeholder_seq += 1
        tag = self._console_placeholder_seq
        placeholder = f"[explain #{tag}] thinking…"
        self._append_console(placeholder)
        context = f"action={self.selected_action_id}"
        snippet = text[-4000:]

        def worker():
            explanation = self.llm.explain(snippet, context=context)
            self.after(0, self._replace_console_placeholder, placeholder, f"[explain #{tag}] {explanation}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_suggest(self):
        """Ask the local LLM for next-step ideas. Threaded like Explain above."""
        state = {
            "phase": self.current_phase.get(),
            "target": self.target_var.get().strip(),
            "last_action": self.selected_action_id or "none",
        }
        self._console_placeholder_seq += 1
        tag = self._console_placeholder_seq
        placeholder = f"[suggest #{tag}] thinking…"
        self._append_console(placeholder)

        def worker():
            suggestion = self.llm.suggest_next(state)
            self.after(0, self._replace_console_placeholder, placeholder, f"[suggest #{tag}] {suggestion}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_reload_custom(self):
        """Re-read the custom/AI command store (e.g. after the on-box AI appended to it)."""
        self.custom_actions = custom.load_custom_actions(self.custom_path)
        self._refresh_tree()
        self._append_console(f"[custom] reloaded {len(self.custom_actions)} command(s) from {self.custom_path}")

    def _on_add_command(self):
        CustomCommandDialog(self)

    def _on_add_finding(self):
        dialog = FindingDialog(self, default_target=self.target_var.get().strip())
        self.wait_window(dialog)
        if dialog.result:
            finding = self.findings.add(**dialog.result)
            self._append_console(f"[finding added] {finding.id} — {finding.title}")

    def _on_generate_report(self):
        written = report.generate(self.output_dir, engagement=self.config_data.get("inventory"))
        self._append_console(f"[report] generated: {written['report_md']}")
        messagebox.showinfo("Report generated", f"Report written to:\n{written['report_md']}")

    def _on_save_console(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.console.get("1.0", "end"))

    # ------------------------------------------------------------------
    # AI chat panel
    # ------------------------------------------------------------------
    def _append_chat(self, role: str, text: str):
        who = "You" if role == "user" else "AI"
        self.chat_view.configure(state="normal")
        self.chat_view.insert("end", f"{who}: {text.rstrip()}\n\n", (role,))
        self.chat_view.configure(state="disabled")
        self.chat_view.see("end")

    def _append_chat_placeholder(self) -> str:
        self._chat_placeholder_seq += 1
        tag = f"thinking_{self._chat_placeholder_seq}"
        self.chat_view.configure(state="normal")
        self.chat_view.insert("end", "AI: thinking…\n\n", ("meta", tag))
        self.chat_view.configure(state="disabled")
        self.chat_view.see("end")
        return tag

    def _replace_chat_placeholder(self, placeholder_tag: str, role: str, text: str):
        who = "You" if role == "user" else "AI"
        self.chat_view.configure(state="normal")
        ranges = self.chat_view.tag_ranges(placeholder_tag)
        if ranges:
            start, end = ranges[0], ranges[1]
            self.chat_view.delete(start, end)
            self.chat_view.insert(start, f"{who}: {text.rstrip()}\n\n", (role,))
        else:
            self.chat_view.insert("end", f"{who}: {text.rstrip()}\n\n", (role,))
        self.chat_view.configure(state="disabled")
        self.chat_view.see("end")

    def _on_chat_send_event(self, event):
        self._on_chat_send()
        return "break"  # swallow the Enter so it doesn't also insert a newline

    def _on_chat_send(self):
        text = self.chat_input.get("1.0", "end").strip()
        if not text:
            return
        self.chat_input.delete("1.0", "end")
        self._send_chat_message(text)

    def _on_chat_recon_plan(self):
        self._send_chat_message(
            "What's the stealthiest order of recon commands to discover the blue team on the "
            "in-scope subnet? Start with passive/quiet host discovery."
        )

    def _chat_context_summary(self) -> str:
        target = self.target_var.get().strip() or "none set"
        phase_label = dict(PHASE_CHOICES).get(self.current_phase.get(), str(self.current_phase.get()))
        return (
            f"Operator context — phase: {phase_label}; day: {self.day.get()}; "
            f"target field: {target}; scope status: {self.scope_badge_text.get()}; "
            f"stealth mode: {'on' if self.stealth_mode.get() else 'off'}."
        )

    def _send_chat_message(self, text: str):
        """Thread the chat call so the GUI never blocks on the (localhost-only) LLM. Keeps a
        capped conversation history for multi-turn context."""
        self._append_chat("user", text)
        self.chat_history.append({"role": "user", "content": text})
        self.chat_history = self.chat_history[-12:]

        placeholder_tag = self._append_chat_placeholder()
        extra_system = self._chat_context_summary()
        history_snapshot = list(self.chat_history)

        def worker():
            reply = self.llm.chat(history_snapshot, extra_system=extra_system)
            self.after(0, self._on_chat_reply, reply, placeholder_tag)

        threading.Thread(target=worker, daemon=True).start()

    def _on_chat_reply(self, reply: str | None, placeholder_tag: str):
        from dogpark.llm import canned_recon_plan

        body = reply.strip() if reply else canned_recon_plan()
        self._replace_chat_placeholder(placeholder_tag, "ai", body)
        self.chat_history.append({"role": "assistant", "content": body})
        self.chat_history = self.chat_history[-12:]


class FindingDialog(tk.Toplevel):
    def __init__(self, parent, default_target: str = ""):
        super().__init__(parent)
        self.title("Add finding")
        self.result = None

        fields = ["target", "severity", "title", "evidence_path", "impact", "remediation"]
        self.vars = {f: tk.StringVar() for f in fields}
        self.vars["target"].set(default_target)
        self.vars["severity"].set("Info")

        for field in fields:
            row = ttk.Frame(self)
            row.pack(fill="x", padx=8, pady=2)
            ttk.Label(row, text=field, width=14).pack(side="left")
            if field == "severity":
                ttk.Combobox(
                    row, textvariable=self.vars[field], values=list(evidence.SEVERITIES), state="readonly"
                ).pack(side="left", fill="x", expand=True)
            else:
                ttk.Entry(row, textvariable=self.vars[field]).pack(side="left", fill="x", expand=True)

        button_row = ttk.Frame(self)
        button_row.pack(fill="x", padx=8, pady=8)
        ttk.Button(button_row, text="Add", command=self._on_add).pack(side="right")
        ttk.Button(button_row, text="Cancel", command=self.destroy).pack(side="right", padx=4)

    def _on_add(self):
        self.result = {k: v.get() for k, v in self.vars.items()}
        self.destroy()


class CustomCommandDialog(tk.Toplevel):
    """Add a user/AI command to the JSON store. Same safety screen as the module API — a
    destructive template is refused here too."""

    def __init__(self, app: "DogparkApp"):
        super().__init__(app)
        self.app = app
        self.title("Add command")
        self.geometry("560x340")

        self.vars = {
            "label": tk.StringVar(),
            "phase": tk.StringVar(value="1"),
            "risk": tk.StringVar(value="normal"),
            "template": tk.StringVar(),
            "needs": tk.StringVar(value="target output"),
            "description": tk.StringVar(),
        }
        hints = {
            "template": "command with {placeholders}, e.g. nmap -sV {target} -oA {output}/x",
            "needs": "space-separated placeholder names this command needs",
        }
        for field, var in self.vars.items():
            row = ttk.Frame(self)
            row.pack(fill="x", padx=8, pady=3)
            ttk.Label(row, text=field, width=12).pack(side="left")
            if field == "risk":
                ttk.Combobox(row, textvariable=var, values=list(tools.RISK_LEVELS), state="readonly").pack(
                    side="left", fill="x", expand=True
                )
            else:
                ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
            if field in hints:
                ttk.Label(self, text=hints[field], foreground=PALETTE["muted"]).pack(anchor="w", padx=86)

        ttk.Label(
            self,
            text="Added commands follow the same rules: scope-locked, manual Run, and destructive "
            "templates are refused.",
            wraplength=520,
            foreground=PALETTE["muted"],
        ).pack(anchor="w", padx=10, pady=(6, 0))

        button_row = ttk.Frame(self)
        button_row.pack(fill="x", padx=8, pady=8)
        ttk.Button(button_row, text="Add", command=self._on_add).pack(side="right")
        ttk.Button(button_row, text="Cancel", command=self.destroy).pack(side="right", padx=4)

    def _on_add(self):
        try:
            phase = int(self.vars["phase"].get() or "1")
        except ValueError:
            phase = 1
        entry = {
            "label": self.vars["label"].get().strip(),
            "phase": phase,
            "risk": self.vars["risk"].get(),
            "template": self.vars["template"].get().strip(),
            "needs": self.vars["needs"].get().split(),
            "description": self.vars["description"].get().strip(),
        }
        ok, msg = custom.add_custom_action(entry, self.app.custom_path)
        if ok:
            self.app._on_reload_custom()
            self.destroy()
        else:
            messagebox.showerror("Command refused", msg)


def main():
    app = DogparkApp()
    app.mainloop()


if __name__ == "__main__":
    main()
