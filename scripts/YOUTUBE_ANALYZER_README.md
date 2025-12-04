# YouTube Video Analyzer

A powerful tool for security researchers and bug bounty hunters to analyze YouTube videos for security-related content, techniques, and tools.

## Features

- **Audio Extraction**: Downloads audio from YouTube videos
- **Speech-to-Text**: Transcribes spoken content using OpenAI's Whisper
- **Security Analysis**: Identifies potential vulnerabilities, techniques, and tools
- **Report Generation**: Creates detailed markdown and JSON reports
- **Command Line Interface**: Easy to use from the terminal

## Installation

1. Install system dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install -y ffmpeg
   
   # macOS
   brew install ffmpeg
   
   # Windows (with Chocolatey)
   choco install ffmpeg
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements-youtube.txt
   ```

## Usage

### Basic Usage

```bash
python youtube_analyzer.py https://www.youtube.com/watch?v=VIDEO_ID
```

### Advanced Options

```bash
# Specify custom output directory
python youtube_analyzer.py https://www.youtube.com/watch?v=VIDEO_ID --output /path/to/output

# Get help
python youtube_analyzer.py --help
```

### Example Output

```
Analysis Complete: Advanced Web Application Security Testing Techniques
======================================================================
Duration: 12m 45s
Word Count: 2456
Unique Words: 876

Potential Techniques: xss, csrf, sqli, jwt, oauth
Potential Vulnerabilities: XSS, CSRF, SQLI
Security Tools Mentioned: burp, nmap, sqlmap, nuclei

Top 10 Most Relevant Terms:
  injection: 24
  security: 19
  vulnerability: 15
  request: 14
  server: 12
  attack: 11
  web: 10
  application: 9
  parameter: 8
  payload: 7

Full report and transcript saved to disk.
```

## Output Files

For each analyzed video, the following files are created in the output directory:

- `analysis.json`: Complete analysis in JSON format
- `report.md`: Detailed markdown report
- `transcript.txt`: Full text transcript

## Integration with Recon Workflow

You can integrate this tool into your recon workflow by:

1. Creating a script to process multiple videos
2. Adding it to your automation pipeline
3. Using the JSON output for further analysis

## Requirements

- Python 3.8+
- FFmpeg
- 4GB+ RAM (for Whisper model)
- Internet connection (for downloading videos)

## Troubleshooting

- **Installation Issues**: Make sure you have all system dependencies installed
- **Transcription Failures**: Try using a different Whisper model (edit the code to change `base` to `tiny` or `small`)
- **Performance**: For better performance, use a GPU with CUDA support

## License

This tool is provided for educational and research purposes only. Use responsibly and only on videos you have permission to analyze.
