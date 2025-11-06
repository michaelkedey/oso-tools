from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from pyfiglet import Figlet
from .constants import APP_NAME, VERSION

console = Console()

def banner(show: bool = True):
    if not show:
        return
    f = Figlet(font="slant")
    text = f.renderText(APP_NAME)
    console.print(Panel(Text(text, justify="center"), subtitle=f"v{VERSION}", padding=(0,1)))
