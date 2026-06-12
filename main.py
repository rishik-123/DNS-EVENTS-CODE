import os
import sys
import json
import time
import signal
import logging
import threading
from datetime import datetime
from typing import Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich import box

# Add current folder to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from collectors.dns_sniffer import DNSSniffer
from engine.correlation import CorrelationEngine
from utils.kafka_producer import DNSKafkaProducer

# Configure python logger (writes debug logs to a separate file so console stays clean for the UI)
os.makedirs(config.LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(config.LOG_DIR, "agent_debug.log"),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("agent_main")

# Global UI and tracking state
console = Console()
event_counter = 0
alert_counter = 0
dga_counter = 0
tunneling_counter = 0
typosquat_counter = 0
threat_counter = 0
coruna_counter = 0

latest_events: List[Dict[str, Any]] = []
latest_events_lock = threading.Lock()
file_write_lock = threading.Lock()
stats_lock = threading.Lock()

correlation_engine: CorrelationEngine = None
sniffer: DNSSniffer = None
kafka_producer: DNSKafkaProducer = None

import concurrent.futures
# Thread pool for offloading DNS packet processing to avoid blocking the Scapy capture loop
event_executor = concurrent.futures.ThreadPoolExecutor(max_workers=20, thread_name_prefix="event_handler")


def handle_correlated_event(raw_event: Dict[str, Any]):
    """
    Callback function that schedules the raw event to be processed
    asynchronously inside the thread pool to keep packet capture non-blocking.
    """
    event_executor.submit(_async_handle_correlated_event, raw_event)


def _async_handle_correlated_event(raw_event: Dict[str, Any]):
    global event_counter, alert_counter, dga_counter, tunneling_counter, typosquat_counter, threat_counter, coruna_counter
    
    try:
        # Pass to correlation engine
        soc_event = correlation_engine.process_event(raw_event)
        
        # Build the final wrapper structure required by the user
        log_wrapper = {
            "event_id": soc_event["event_id"],
            "timestamp": soc_event["timestamp"],
            "file_details": {
                "output_file": config.OUTPUT_LOG_FILE,
                "format": "JSON-Lines (NDJSON)"
            },
            "data": soc_event
        }
        
        # Write to local file (thread-safe append with immediate flush/sync to avoid caching delays)
        with file_write_lock:
            try:
                with open(config.OUTPUT_LOG_FILE, "a") as f:
                    f.write(json.dumps(log_wrapper) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as fe:
                logger.error(f"Failed to write event to disk: {fe}")

        # Publish to Kafka if enabled
        if kafka_producer:
            kafka_producer.send_event(log_wrapper)

        # Update statistics (thread-safe)
        with stats_lock:
            event_counter += 1
            event_alerts = soc_event.get("alerts", [])
            if event_alerts:
                alert_counter += 1
                
            for alert in event_alerts:
                if "TUNNELING" in alert:
                    tunneling_counter += 1
                elif "DGA" in alert:
                    dga_counter += 1
                elif "TYPOSQUATTING" in alert:
                    typosquat_counter += 1
                elif "THREAT" in alert:
                    threat_counter += 1
                elif "CORUNA" in alert:
                    coruna_counter += 1

        # Keep track of latest 10 events for UI scroll
        with latest_events_lock:
            latest_events.insert(0, soc_event)
            if len(latest_events) > 10:
                latest_events.pop()
                
    except Exception as e:
        logger.error(f"Error handling captured DNS event: {e}", exc_info=True)


def generate_dashboard_layout() -> Panel:
    """Generates the Rich Terminal Panel containing statistics and the event table."""
    # Stats sub-table
    stats_table = Table(box=box.SIMPLE, expand=True)
    stats_table.add_column("[cyan]Metric[/cyan]", justify="left")
    stats_table.add_column("[cyan]Value[/cyan]", justify="right")
    
    mode_text = "[bold yellow]SIMULATION[/bold yellow]" if config.SIMULATION_MODE else "[bold green]LIVE SNIFFER[/bold green]"
    stats_table.add_row("Agent Operation Mode", mode_text)
    stats_table.add_row("Total Captured DNS Events", f"[bold white]{event_counter}[/bold white]")
    stats_table.add_row("Total Security Alerts Triggered", f"[bold red]{alert_counter}[/bold red]" if alert_counter > 0 else "0")
    stats_table.add_row("  └─ DNS Tunneling Detections", f"[bold light_salmon3]{tunneling_counter}[/bold light_salmon3]" if tunneling_counter > 0 else "0")
    stats_table.add_row("  └─ DGA Beaconing Detections", f"[bold orange3]{dga_counter}[/bold orange3]" if dga_counter > 0 else "0")
    stats_table.add_row("  └─ Typosquatting Alerts", f"[bold yellow]{typosquat_counter}[/bold yellow]" if typosquat_counter > 0 else "0")
    stats_table.add_row("  └─ Threat Intel Matches", f"[bold red1]{threat_counter}[/bold red1]" if threat_counter > 0 else "0")
    stats_table.add_row("  └─ Coruna Exploit Kit Matches", f"[bold magenta]{coruna_counter}[/bold magenta]" if coruna_counter > 0 else "0")

    # Target info table
    target_table = Table(box=box.SIMPLE, expand=True)
    target_table.add_column("[cyan]Asset / Identity Context[/cyan]", justify="left")
    target_table.add_column("[cyan]Value[/cyan]", justify="right")
    target_table.add_row("Host Name", config.ASSET_CONTEXT.get("hostname", "unknown"))
    target_table.add_row("Asset Criticality", f"[bold red]{config.ASSET_CONTEXT.get('criticality')}[/bold red]")
    target_table.add_row("Department / Unit", f"{config.ASSET_CONTEXT.get('department')} ({config.ASSET_CONTEXT.get('business_unit')})")
    target_table.add_row("Current Session User", f"{config.USER_CONTEXT.get('username')} ([italic]{config.USER_CONTEXT.get('privilege')}[/italic])")

    # Header panels layout
    summary_table = Table.grid(expand=True)
    summary_table.add_column(ratio=6)
    summary_table.add_column(ratio=6)
    summary_table.add_row(stats_table, target_table)

    # Latest Events table
    events_table = Table(box=box.MINIMAL_DOUBLE_HEAD, expand=True, padding=(0, 1))
    events_table.add_column("[cyan]Time (UTC)[/cyan]", width=12)
    events_table.add_column("[cyan]Query Domain[/cyan]", width=28)
    events_table.add_column("[cyan]Type[/cyan]", width=5, justify="center")
    events_table.add_column("[cyan]Process (PID)[/cyan]", width=18)
    events_table.add_column("[cyan]Location[/cyan]", width=18)
    events_table.add_column("[cyan]Alerts / Findings[/cyan]")

    with latest_events_lock:
        for ev in latest_events:
            dns_q = ev["dns"]["query"]
            dns_t = ev["dns"]["query_type"]
            proc_name = f"{ev['process']['process_name']} ({ev['process']['pid']})"
            
            # Extract first location or default
            locs = ev.get("geolocation", [])
            loc_str = "Internal"
            if locs:
                loc_str = f"{locs[0].get('country', 'unknown')} ({locs[0].get('city', 'unknown')})"
            elif ev["dns"]["response_code"] == "NXDOMAIN":
                loc_str = "[dim]NXDOMAIN[/dim]"

            # Map alerts to colored strings
            alert_labels = []
            for alert in ev.get("alerts", []):
                if "TUNNELING" in alert:
                    alert_labels.append("[bold light_salmon3]TUNNELING[/bold light_salmon3]")
                elif "DGA" in alert:
                    alert_labels.append("[bold orange3]DGA[/bold orange3]")
                elif "TYPOSQUATTING" in alert:
                    alert_labels.append("[bold yellow]TYPOSQUAT[/bold yellow]")
                elif "CORUNA" in alert:
                    alert_labels.append("[bold magenta]CORUNA_EXPLOIT[/bold magenta]")
                elif "THREAT" in alert:
                    alert_labels.append(f"[bold red]THREAT_INTEL({ev['threat_intel']['threat_category'].upper()})[/bold red]")
                elif "TTL" in alert:
                    alert_labels.append("[yellow]LOW_TTL[/yellow]")
                elif "NXDOMAIN" in alert:
                    alert_labels.append("[dim yellow]NXDOMAIN_BURST[/dim yellow]")
            
            alert_str = ", ".join(alert_labels) if alert_labels else "[green]BENIGN[/green]"
            
            # Parse timestamp to clean output
            time_part = ev["timestamp"].split("T")[1].replace("Z", "")
            
            events_table.add_row(
                time_part,
                dns_q,
                dns_t,
                proc_name,
                loc_str,
                alert_str
            )

    # Master Layout
    main_table = Table.grid(expand=True)
    main_table.add_row(Panel(summary_table, title="[bold white]Telemetry Statistics[/bold white]", border_style="cyan"))
    main_table.add_row(Panel(events_table, title="[bold white]Live SOC Event Stream[/bold white]", border_style="cyan"))

    master_panel = Panel(
        main_table,
        title="[bold white]DEEPCYTES DNS AGENT - MINI SOC TELEMETRY COLLECTOR[/bold white]",
        border_style="bright_blue",
        box=box.ROUNDED
    )
    return master_panel


def signal_handler(sig, frame):
    """Gracefully terminates the sniffer and processes on Ctrl+C."""
    console.print("\n[bold red]Stopping DeepCytes DNS Agent...[/bold red]")
    if sniffer:
        sniffer.stop();
    if kafka_producer:
        kafka_producer.close()
    console.print("[bold green]Agent shut down successfully. Logs saved to: [/bold green]" + config.OUTPUT_LOG_FILE)
    sys.exit(0)


def main():
    global correlation_engine, sniffer, kafka_producer
    
    # Reconfigure stdout to be unbuffered (immediate write-through) to solve terminal latency
    try:
        sys.stdout.reconfigure(write_through=True)
    except Exception:
        pass

    # Catch Ctrl+C signals
    signal.signal(signal.SIGINT, signal_handler)
    
    console.print("[bold green]Starting DeepCytes DNS Security Agent...[/bold green]")
    console.print(f"Working Directory: [cyan]{config.BASE_DIR}[/cyan]")
    console.print(f"Output File: [cyan]{config.OUTPUT_LOG_FILE}[/cyan]")
    
    # Check for Scapy/Interface permissions if Sniffing mode is active
    if not config.SIMULATION_MODE:
        if sys.platform == "win32":
            # Check for admin privileges on Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                console.print("[bold yellow]WARNING: Running in LIVE SNIFFER mode but not running as Administrator.[/bold yellow]")
                console.print("[yellow]Scapy requires administrative rights to capture raw network sockets on Windows.[/yellow]")
                console.print("[yellow]Falling back to SIMULATION MODE for safe, cross-platform validation.[/yellow]")
                config.SIMULATION_MODE = True
        else:
            # Check for root on Linux/Mac
            if os.getuid() != 0:
                console.print("[bold yellow]WARNING: Not running as root. Scapy requires raw socket access. Falling back to Simulation Mode.[/bold yellow]")
                config.SIMULATION_MODE = True
                
    # Initialize Correlation Engine
    correlation_engine = CorrelationEngine()
    
    # Initialize Kafka Producer
    kafka_producer = DNSKafkaProducer()
    
    # Initialize DNS Sniffer / Simulator
    sniffer = DNSSniffer(callback=handle_correlated_event)
    sniffer.start()
    
    console.print("[bold green]Initialization complete! Launching dashboard interface...[/bold green]")
    time.sleep(1.0)
    
    # Run dashboard live display
    with Live(generate_dashboard_layout(), refresh_per_second=2, screen=False) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(generate_dashboard_layout())
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
