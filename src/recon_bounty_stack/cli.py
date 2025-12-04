"""
Command-line interface for Recon Bounty Stack.

Provides CLI commands for running scans, checking status,
and managing authorization.
"""

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from recon_bounty_stack import __version__
from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.pipeline import Pipeline
from recon_bounty_stack.utils.legal import LegalAuthorizationShield

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="recon-bounty")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.pass_context
def main(ctx: click.Context, verbose: bool, output: str | None) -> None:
    """Recon Bounty Stack - Automated Bug Bounty Reconnaissance

    A professional-grade reconnaissance automation framework for authorized
    security testing and bug bounty hunting.

    Examples:

        # Run a quick scan
        recon-bounty scan example.com --mode quick

        # Check scan status
        recon-bounty status

        # Create authorization for a target
        recon-bounty auth create example.com --client "Client Name"
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    # Load config
    config = Config.from_env()
    if output:
        config.output_dir = Path(output)
    ctx.obj["config"] = config


@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option(
    "--mode",
    type=click.Choice(["quick", "full", "stealth"]),
    default="quick",
    help="Scan mode: quick (fast), full (comprehensive), stealth (slow/quiet)",
)
@click.option("--dry-run", is_flag=True, help="Simulate scan without executing")
@click.option("--resume", is_flag=True, help="Resume from last completed stage")
@click.option("--skip-auth", is_flag=True, help="Skip authorization check (dangerous!)")
@click.pass_context
def scan(
    ctx: click.Context,
    targets: tuple,
    mode: str,
    dry_run: bool,
    resume: bool,
    skip_auth: bool,
) -> None:
    """Run reconnaissance scan against TARGET(s).

    Examples:

        # Scan a single target
        recon-bounty scan example.com

        # Scan multiple targets
        recon-bounty scan target1.com target2.com

        # Dry run (simulate only)
        recon-bounty scan example.com --dry-run

        # Resume a previous scan
        recon-bounty scan example.com --resume
    """
    config = ctx.obj["config"]
    targets_list = list(targets)

    console.print(f"\n[bold blue]Recon Bounty Stack v{__version__}[/bold blue]")
    console.print(f"Mode: {mode}")
    console.print(f"Targets: {', '.join(targets_list)}")
    console.print()

    if skip_auth:
        console.print(
            "[bold red]⚠️  WARNING: Skipping authorization check![/bold red]"
        )
        console.print(
            "[yellow]Scanning unauthorized targets may be illegal![/yellow]"
        )
        if not click.confirm("Are you sure you want to continue?"):
            raise SystemExit(1)

    # Create and run pipeline
    pipeline = Pipeline(config=config, dry_run=dry_run)

    try:
        results = pipeline.run(
            targets=targets_list,
            resume=resume,
            skip_auth=skip_auth,
        )

        # Show summary
        if "error" in results:
            console.print(f"\n[red]Error: {results['error']}[/red]")
            raise SystemExit(1)

        summary = results.get("summary", {})
        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(f"Duration: {results.get('duration_seconds', 0):.1f}s")

        if summary:
            console.print("\n[bold]Summary:[/bold]")
            for key, value in summary.items():
                console.print(f"  {key}: {value}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise SystemExit(130) from None
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise SystemExit(1) from e


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show current scan status and statistics."""
    config = ctx.obj["config"]
    pipeline = Pipeline(config=config)

    status_data = pipeline.status()

    # Create status table
    table = Table(title="Pipeline Status")
    table.add_column("Stage", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="green")

    for stage in status_data["stages"]:
        status_icon = "✅" if stage["completed"] else "⏳"
        table.add_row(stage["name"], stage["description"], status_icon)

    console.print(table)

    # Show summary if available
    summary = status_data.get("summary", {})
    if summary:
        console.print("\n[bold]Statistics:[/bold]")
        for key, value in summary.items():
            console.print(f"  {key}: {value}")


@main.command()
@click.pass_context
def reset(ctx: click.Context) -> None:
    """Reset pipeline status for a fresh run."""
    config = ctx.obj["config"]
    pipeline = Pipeline(config=config)

    if click.confirm("This will reset all pipeline status. Continue?"):
        pipeline.reset()
        console.print("[green]Pipeline status reset successfully[/green]")


@main.group()
def auth() -> None:
    """Manage target authorization."""
    pass


@auth.command("create")
@click.argument("target")
@click.option("--client", required=True, help="Client name")
@click.pass_context
def auth_create(ctx: click.Context, target: str, client: str) -> None:
    """Create authorization template for a target.

    This creates a JSON template that must be filled out with
    proper client authorization details before scanning.
    """
    config = ctx.obj["config"]
    shield = LegalAuthorizationShield(str(config.auth_dir))

    output_file = shield.create_authorization_template(target, client)
    console.print("\n[green]Authorization template created:[/green]")
    console.print(f"  {output_file}")
    console.print(
        "\n[yellow]⚠️  Important: Fill in all placeholder values and get client signature before scanning![/yellow]"
    )


@auth.command("check")
@click.argument("target")
@click.pass_context
def auth_check(ctx: click.Context, target: str) -> None:
    """Check authorization status for a target."""
    config = ctx.obj["config"]
    shield = LegalAuthorizationShield(str(config.auth_dir))

    authorized, reason, auth_data = shield.check_authorization(target)

    if authorized:
        console.print(f"\n[green]✅ Target {target} is authorized[/green]")
        if auth_data:
            console.print(f"  Client: {auth_data.get('client_name', 'Unknown')}")
            console.print(f"  Valid until: {auth_data.get('end_date', 'Unknown')}")
    else:
        console.print(f"\n[red]❌ Target {target} is NOT authorized[/red]")
        console.print(f"  Reason: {reason}")


@auth.command("list")
@click.pass_context
def auth_list(ctx: click.Context) -> None:
    """List all authorization files."""
    config = ctx.obj["config"]
    auth_dir = Path(config.auth_dir)

    if not auth_dir.exists():
        console.print("[yellow]No authorization directory found[/yellow]")
        return

    auth_files = list(auth_dir.glob("*_authorization.json"))
    if not auth_files:
        console.print("[yellow]No authorization files found[/yellow]")
        return

    table = Table(title="Authorization Files")
    table.add_column("Target", style="cyan")
    table.add_column("Client", style="white")
    table.add_column("Valid Until", style="green")

    import json

    for auth_file in auth_files:
        try:
            with open(auth_file) as f:
                data = json.load(f)
            table.add_row(
                data.get("target", "Unknown"),
                data.get("client_name", "Unknown"),
                data.get("end_date", "Unknown")[:10],
            )
        except (json.JSONDecodeError, OSError):
            table.add_row(auth_file.stem, "Error", "N/A")

    console.print(table)


@main.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show version information."""
    console.print(f"Recon Bounty Stack v{__version__}")
    console.print("Copyright (c) 2025 DoctorMen")
    console.print("License: Proprietary")


if __name__ == "__main__":
    main()
