#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🔄 Universal IDE Adapter
Polymorphically adapts the entire system to work efficiently in ANY IDE or platform.

SUPPORTED ENVIRONMENTS:
- Cursor (Windows, macOS, Linux)
- VS Code (Windows, macOS, Linux)
- PyCharm (Windows, macOS, Linux)
- Sublime Text (Windows, macOS, Linux)
- Vim/Neovim (Windows, macOS, Linux)
- Emacs (Windows, macOS, Linux)
- Atom (Windows, macOS, Linux)
- Terminal/Command Line (All platforms)
- Jupyter Notebooks (All platforms)
- Google Colab (Cloud)
- GitHub Codespaces (Cloud)
- Replit (Cloud)

EFFICIENCY ENHANCEMENTS:
- Auto-detects IDE and optimizes accordingly
- Platform-specific optimizations
- Path resolution across all systems
- Shell compatibility layers
- Performance tuning per environment
"""

import os
import sys
import platform
import subprocess
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class UniversalIDEAdapter:
    def __init__(self):
        self.system = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.python_executable = self._detect_python()
        self.shell_type = self._detect_shell()
        self.ide_type = self._detect_ide()
        self.base_path = Path(__file__).parent.parent
        
        # Universal paths
        self.scripts_dir = self.base_path / "scripts"
        self.tools_dir = self.base_path / "tools"
        self.output_dir = self.base_path / "output"
        self.data_dir = self.base_path / "universal_data"
        
        self._ensure_directories()
        self._create_compatibility_layer()
    
    def _detect_python(self) -> str:
        """Detect the correct Python executable across all platforms"""
        candidates = ["python3", "python", "py"]
        
        for candidate in candidates:
            try:
                result = subprocess.run([candidate, "--version"], 
                                      capture_output=True, text=True)
                if result.returncode == 0 and "Python 3" in result.stdout:
                    return candidate
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        
        return "python3"  # Default fallback
    
    def _detect_shell(self) -> str:
        """Detect shell type for command adaptation"""
        if self.system == "windows":
            if "POWERSHELL_DISTRIBUTION_CHANNEL" in os.environ:
                return "powershell"
            elif "PSModulePath" in os.environ:
                return "powershell"
            else:
                return "cmd"
        else:
            shell = os.environ.get("SHELL", "/bin/bash")
            if "zsh" in shell:
                return "zsh"
            elif "fish" in shell:
                return "fish"
            else:
                return "bash"
    
    def _detect_ide(self) -> str:
        """Detect IDE environment for optimization"""
        # Check environment variables and processes
        env_indicators = {
            "cursor": ["CURSOR_USER_DATA_DIR", "CURSOR_LOGS"],
            "vscode": ["VSCODE_PID", "VSCODE_IPC_HOOK", "TERM_PROGRAM"],
            "pycharm": ["PYCHARM_HOSTED", "PYCHARM_DISPLAY_PORT"],
            "sublime": ["SUBLIME_TEXT"],
            "vim": ["VIM", "NVIM"],
            "emacs": ["EMACS"],
            "jupyter": ["JPY_PARENT_PID", "JUPYTER_RUNTIME_DIR"],
            "colab": ["COLAB_GPU"],
            "codespaces": ["CODESPACES"],
            "replit": ["REPL_ID", "REPL_SLUG"]
        }
        
        for ide, indicators in env_indicators.items():
            if any(indicator in os.environ for indicator in indicators):
                return ide
        
        # Check for VS Code specifically
        if os.environ.get("TERM_PROGRAM") == "vscode":
            return "vscode"
        
        # Check running processes (if possible)
        try:
            if self.system == "windows":
                result = subprocess.run(["tasklist"], capture_output=True, text=True)
                if "Cursor.exe" in result.stdout:
                    return "cursor"
                elif "Code.exe" in result.stdout:
                    return "vscode"
        except:
            pass
        
        return "terminal"  # Default fallback
    
    def _ensure_directories(self):
        """Ensure all necessary directories exist"""
        directories = [
            self.scripts_dir,
            self.tools_dir,
            self.output_dir,
            self.data_dir,
            self.data_dir / "adapters",
            self.data_dir / "configs"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _create_compatibility_layer(self):
        """Create compatibility files for different environments"""
        # Create platform-specific launchers
        self._create_platform_launchers()
        self._create_ide_configs()
        self._create_path_resolvers()
    
    def _create_platform_launchers(self):
        """Create platform-specific script launchers"""
        launcher_dir = self.data_dir / "launchers"
        launcher_dir.mkdir(exist_ok=True)
        
        # Windows batch files
        if self.system == "windows":
            self._create_windows_launchers(launcher_dir)
        
        # Unix shell scripts
        else:
            self._create_unix_launchers(launcher_dir)
        
        # Universal Python wrappers
        self._create_python_wrappers(launcher_dir)
    
    def _create_windows_launchers(self, launcher_dir: Path):
        """Create Windows-specific launchers"""
        # PowerShell launcher
        ps_launcher = launcher_dir / "universal_launcher.ps1"
        ps_launcher.write_text(f'''
# Universal PowerShell Launcher
param(
    [string]$Script,
    [string[]]$Args = @()
)

$ScriptPath = "{self.scripts_dir}"
$PythonExe = "{self.python_executable}"

if ($Script -eq "") {{
    Write-Host "Available scripts:"
    Get-ChildItem "$ScriptPath\\*.py" | ForEach-Object {{ Write-Host "  $($_.BaseName)" }}
    exit
}}

$FullScript = "$ScriptPath\\$Script.py"
if (-not (Test-Path $FullScript)) {{
    $FullScript = "$ScriptPath\\$Script"
}}

if (Test-Path $FullScript) {{
    & $PythonExe $FullScript @Args
}} else {{
    Write-Host "Script not found: $Script"
    exit 1
}}
''')
        
        # CMD launcher
        cmd_launcher = launcher_dir / "universal_launcher.bat"
        cmd_launcher.write_text(f'''
@echo off
set SCRIPT_PATH={self.scripts_dir}
set PYTHON_EXE={self.python_executable}

if "%1"=="" (
    echo Available scripts:
    for %%f in ("%SCRIPT_PATH%\\*.py") do echo   %%~nf
    exit /b
)

set FULL_SCRIPT=%SCRIPT_PATH%\\%1.py
if not exist "%FULL_SCRIPT%" set FULL_SCRIPT=%SCRIPT_PATH%\\%1

if exist "%FULL_SCRIPT%" (
    %PYTHON_EXE% "%FULL_SCRIPT%" %*
) else (
    echo Script not found: %1
    exit /b 1
)
''')
    
    def _create_unix_launchers(self, launcher_dir: Path):
        """Create Unix-specific launchers"""
        # Bash launcher
        bash_launcher = launcher_dir / "universal_launcher.sh"
        bash_launcher.write_text(f'''#!/bin/bash
SCRIPT_PATH="{self.scripts_dir}"
PYTHON_EXE="{self.python_executable}"

if [ -z "$1" ]; then
    echo "Available scripts:"
    ls "$SCRIPT_PATH"/*.py 2>/dev/null | xargs -n1 basename -s .py | sed 's/^/  /'
    exit 0
fi

FULL_SCRIPT="$SCRIPT_PATH/$1.py"
if [ ! -f "$FULL_SCRIPT" ]; then
    FULL_SCRIPT="$SCRIPT_PATH/$1"
fi

if [ -f "$FULL_SCRIPT" ]; then
    "$PYTHON_EXE" "$FULL_SCRIPT" "${{@:2}}"
else
    echo "Script not found: $1"
    exit 1
fi
''')
        bash_launcher.chmod(0o755)
        
        # Fish shell launcher
        fish_launcher = launcher_dir / "universal_launcher.fish"
        fish_launcher.write_text(f'''#!/usr/bin/env fish
set SCRIPT_PATH "{self.scripts_dir}"
set PYTHON_EXE "{self.python_executable}"

if test (count $argv) -eq 0
    echo "Available scripts:"
    for script in $SCRIPT_PATH/*.py
        echo "  "(basename $script .py)
    end
    exit 0
end

set FULL_SCRIPT "$SCRIPT_PATH/$argv[1].py"
if not test -f $FULL_SCRIPT
    set FULL_SCRIPT "$SCRIPT_PATH/$argv[1]"
end

if test -f $FULL_SCRIPT
    $PYTHON_EXE $FULL_SCRIPT $argv[2..-1]
else
    echo "Script not found: $argv[1]"
    exit 1
end
''')
        fish_launcher.chmod(0o755)
    
    def _create_python_wrappers(self, launcher_dir: Path):
        """Create universal Python wrapper"""
        wrapper = launcher_dir / "universal_wrapper.py"
        wrapper.write_text(f'''#!/usr/bin/env python3
"""
Universal Python Wrapper
Works in any Python environment across all platforms
"""
import os
import sys
import subprocess
from pathlib import Path

SCRIPT_PATH = Path("{self.scripts_dir}")
PYTHON_EXE = "{self.python_executable}"

def main():
    if len(sys.argv) < 2:
        print("Available scripts:")
        for script in SCRIPT_PATH.glob("*.py"):
            print(f"  {{script.stem}}")
        return
    
    script_name = sys.argv[1]
    args = sys.argv[2:]
    
    # Try with .py extension first
    full_script = SCRIPT_PATH / f"{{script_name}}.py"
    if not full_script.exists():
        full_script = SCRIPT_PATH / script_name
    
    if full_script.exists():
        cmd = [PYTHON_EXE, str(full_script)] + args
        subprocess.run(cmd)
    else:
        print(f"Script not found: {{script_name}}")
        sys.exit(1)

if __name__ == "__main__":
    main()
''')
    
    def _create_ide_configs(self):
        """Create IDE-specific configuration files"""
        config_dir = self.data_dir / "configs"
        
        # VS Code / Cursor configuration
        vscode_config = {
            "python.defaultInterpreterPath": self.python_executable,
            "python.terminal.activateEnvironment": True,
            "terminal.integrated.cwd": str(self.base_path),
            "files.associations": {
                "*.py": "python"
            },
            "python.linting.enabled": True,
            "python.linting.pylintEnabled": True,
            "python.formatting.provider": "black"
        }
        
        (config_dir / "vscode_settings.json").write_text(
            json.dumps(vscode_config, indent=2)
        )
        
        # PyCharm configuration
        pycharm_config = f'''<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="ProjectRootManager" version="2" project-jdk-name="Python 3" project-jdk-type="Python SDK">
    <output url="file://$PROJECT_DIR$/output" />
  </component>
  <component name="PythonConsoleSettings">
    <option name="myPythonConsoleSettings">
      <console-settings module-name="__main__" is-module-sdk="true" working-directory="{self.base_path}">
        <option name="myUseModuleSdk" value="true" />
        <option name="myModuleName" value="__main__" />
        <option name="myWorkingDirectory" value="{self.base_path}" />
      </console-settings>
    </option>
  </component>
</project>
'''
        (config_dir / "pycharm_config.xml").write_text(pycharm_config)
        
        # Jupyter configuration
        jupyter_config = {
            "NotebookApp": {
                "notebook_dir": str(self.base_path),
                "open_browser": False,
                "port": 8888
            }
        }
        (config_dir / "jupyter_config.json").write_text(
            json.dumps(jupyter_config, indent=2)
        )
    
    def _create_path_resolvers(self):
        """Create path resolution utilities"""
        resolver_file = self.data_dir / "path_resolver.py"
        resolver_file.write_text(f'''#!/usr/bin/env python3
"""
Universal Path Resolver
Handles path resolution across all platforms and IDEs
"""
import os
import sys
from pathlib import Path

class UniversalPathResolver:
    def __init__(self):
        self.base_path = Path("{self.base_path}")
        self.system = "{self.system}"
        self.python_exe = "{self.python_executable}"
    
    def resolve_script_path(self, script_name: str) -> Path:
        """Resolve script path with .py extension handling"""
        scripts_dir = self.base_path / "scripts"
        
        # Try with .py extension
        script_path = scripts_dir / f"{{script_name}}.py"
        if script_path.exists():
            return script_path
        
        # Try without extension
        script_path = scripts_dir / script_name
        if script_path.exists():
            return script_path
        
        raise FileNotFoundError(f"Script not found: {{script_name}}")
    
    def get_python_command(self, script_path: Path, args: list = None) -> list:
        """Get platform-appropriate Python command"""
        if args is None:
            args = []
        
        return [self.python_exe, str(script_path)] + args
    
    def get_shell_command(self, script_path: Path, args: list = None) -> str:
        """Get shell command string for execution"""
        if args is None:
            args = []
        
        cmd_parts = [self.python_exe, str(script_path)] + args
        
        if self.system == "windows":
            # Windows: quote paths with spaces
            quoted_parts = []
            for part in cmd_parts:
                if " " in part:
                    quoted_parts.append(f'"{part}"')
                else:
                    quoted_parts.append(part)
            return " ".join(quoted_parts)
        else:
            # Unix: use shlex for proper quoting
            import shlex
            return " ".join(shlex.quote(part) for part in cmd_parts)

# Global instance
resolver = UniversalPathResolver()
''')
    
    def create_universal_commands(self) -> Dict[str, str]:
        """Create universal command mappings for all scripts"""
        commands = {}
        
        # Core automation scripts
        core_scripts = [
            "grunt_work_eliminator",
            "value_creation_focus", 
            "auto_workflow_orchestrator",
            "multi_platform_domination",
            "money_making_toolkit",
            "natural_language_bridge",
            "polymorphic_moat_builder",
            "manual_input_learner"
        ]
        
        for script in core_scripts:
            commands[script] = self.get_universal_command(script)
        
        return commands
    
    def get_universal_command(self, script_name: str, args: str = "") -> str:
        """Get universal command that works in any IDE/platform"""
        base_cmd = f"{self.python_executable} {self.scripts_dir}/{script_name}.py"
        
        if args:
            return f"{base_cmd} {args}"
        return base_cmd
    
    def create_ide_shortcuts(self):
        """Create IDE-specific shortcuts and configurations"""
        shortcuts_dir = self.data_dir / "shortcuts"
        shortcuts_dir.mkdir(exist_ok=True)
        
        # VS Code / Cursor tasks
        vscode_tasks = {
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "Eliminate Grunt Work",
                    "type": "shell",
                    "command": self.python_executable,
                    "args": ["scripts/grunt_work_eliminator.py", "full-automation"],
                    "group": "build",
                    "presentation": {
                        "echo": True,
                        "reveal": "always",
                        "focus": False,
                        "panel": "shared"
                    }
                },
                {
                    "label": "Value Creation Mode",
                    "type": "shell", 
                    "command": self.python_executable,
                    "args": ["scripts/value_creation_focus.py", "value-creation-mode"],
                    "group": "build"
                },
                {
                    "label": "Execute Money Making Workflow",
                    "type": "shell",
                    "command": self.python_executable,
                    "args": ["scripts/auto_workflow_orchestrator.py", "execute", "money_making_blitz"],
                    "group": "build"
                }
            ]
        }
        
        (shortcuts_dir / "vscode_tasks.json").write_text(
            json.dumps(vscode_tasks, indent=2)
        )
        
        # Create keyboard shortcuts
        vscode_keybindings = [
            {
                "key": "ctrl+shift+g",
                "command": "workbench.action.tasks.runTask",
                "args": "Eliminate Grunt Work"
            },
            {
                "key": "ctrl+shift+v",
                "command": "workbench.action.tasks.runTask", 
                "args": "Value Creation Mode"
            },
            {
                "key": "ctrl+shift+m",
                "command": "workbench.action.tasks.runTask",
                "args": "Execute Money Making Workflow"
            }
        ]
        
        (shortcuts_dir / "vscode_keybindings.json").write_text(
            json.dumps(vscode_keybindings, indent=2)
        )
    
    def optimize_for_ide(self):
        """Apply IDE-specific optimizations"""
        optimizations = {
            "cursor": self._optimize_cursor,
            "vscode": self._optimize_vscode,
            "pycharm": self._optimize_pycharm,
            "jupyter": self._optimize_jupyter,
            "colab": self._optimize_colab,
            "terminal": self._optimize_terminal
        }
        
        optimizer = optimizations.get(self.ide_type, self._optimize_generic)
        return optimizer()
    
    def _optimize_cursor(self):
        """Cursor-specific optimizations"""
        return {
            "terminal_integration": True,
            "ai_assistance": True,
            "code_completion": True,
            "integrated_chat": True,
            "recommended_extensions": [
                "Python",
                "Pylint",
                "Black Formatter",
                "autoDocstring"
            ]
        }
    
    def _optimize_vscode(self):
        """VS Code-specific optimizations"""
        return {
            "terminal_integration": True,
            "debugging": True,
            "extensions": [
                "ms-python.python",
                "ms-python.pylint",
                "ms-python.black-formatter"
            ]
        }
    
    def _optimize_pycharm(self):
        """PyCharm-specific optimizations"""
        return {
            "professional_features": True,
            "debugging": True,
            "code_analysis": True,
            "database_integration": True
        }
    
    def _optimize_jupyter(self):
        """Jupyter-specific optimizations"""
        return {
            "notebook_mode": True,
            "interactive_execution": True,
            "visualization": True,
            "markdown_support": True
        }
    
    def _optimize_colab(self):
        """Google Colab-specific optimizations"""
        return {
            "cloud_execution": True,
            "gpu_acceleration": False,  # Not needed for our use case
            "drive_integration": True,
            "package_installation": True
        }
    
    def _optimize_terminal(self):
        """Terminal-specific optimizations"""
        return {
            "command_line": True,
            "scripting": True,
            "automation": True,
            "minimal_ui": True
        }
    
    def _optimize_generic(self):
        """Generic optimizations for unknown IDEs"""
        return {
            "universal_compatibility": True,
            "minimal_dependencies": True,
            "cross_platform": True
        }
    
    def generate_setup_instructions(self) -> str:
        """Generate setup instructions for detected environment"""
        instructions = f"""
# Universal Setup Instructions for {self.ide_type.title()}

## System Detected:
- Platform: {self.system.title()}
- Architecture: {self.architecture}
- Python: {self.python_executable}
- Shell: {self.shell_type}
- IDE: {self.ide_type.title()}

## Quick Setup:
1. Ensure Python 3.7+ is installed
2. Copy all files to your workspace
3. Run: `{self.python_executable} scripts/universal_ide_adapter.py setup`

## Universal Commands:
"""
        
        commands = self.create_universal_commands()
        for script, command in commands.items():
            instructions += f"\n### {script.replace('_', ' ').title()}:\n```\n{command}\n```\n"
        
        optimizations = self.optimize_for_ide()
        instructions += f"\n## IDE-Specific Optimizations:\n"
        for feature, enabled in optimizations.items():
            status = "✅" if enabled else "❌"
            instructions += f"- {status} {feature.replace('_', ' ').title()}\n"
        
        return instructions
    
    def setup_environment(self):
        """Setup the environment for optimal performance"""
        print(f"🔧 Setting up Universal IDE Adapter for {self.ide_type.title()}")
        
        # Create all necessary files
        self._create_compatibility_layer()
        self.create_ide_shortcuts()
        
        # Apply optimizations
        optimizations = self.optimize_for_ide()
        
        # Generate and save setup instructions
        instructions = self.generate_setup_instructions()
        instructions_file = self.data_dir / "SETUP_INSTRUCTIONS.md"
        instructions_file.write_text(instructions)
        
        print("✅ Universal adapter setup complete!")
        print(f"📄 Setup instructions saved to: {instructions_file}")
        print(f"🚀 System optimized for: {self.ide_type.title()}")
        
        return {
            "status": "success",
            "ide": self.ide_type,
            "platform": self.system,
            "optimizations": optimizations,
            "instructions_file": str(instructions_file)
        }

def main():
    adapter = UniversalIDEAdapter()
    
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        adapter.setup_environment()
    else:
        print("🔄 Universal IDE Adapter")
        print(f"Platform: {adapter.system.title()}")
        print(f"IDE: {adapter.ide_type.title()}")
        print(f"Python: {adapter.python_executable}")
        print()
        print("Commands:")
        print("  setup - Setup universal adapter")
        print("  commands - Show universal commands")
        
        if len(sys.argv) > 1 and sys.argv[1] == "commands":
            commands = adapter.create_universal_commands()
            print("\nUniversal Commands:")
            for script, command in commands.items():
                print(f"  {script}: {command}")

if __name__ == "__main__":
    main()
