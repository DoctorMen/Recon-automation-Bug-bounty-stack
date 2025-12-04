#!/usr/bin/env python3
"""
YouTube Video Analyzer for Recon Automation Stack

PROPRIETARY AND CONFIDENTIAL
Copyright © 2025 Khallid H Nurse. All Rights Reserved.

This software contains confidential and proprietary information of Khallid H Nurse
and is protected by copyright and other intellectual property laws. Unauthorized
use, disclosure, reproduction, or distribution is strictly prohibited.

Features:
1. Download audio from YouTube videos
2. Transcribe audio to text
3. Security content analysis
4. Structured report generation
"""

# Embedded IP Protection
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

# Import protection and subscription systems
from ip_guardian import ip_guardian
from subscription_manager import subscription_manager

# Validate environment and subscription
ip_guardian.validate_environment()

# Check if running in paid mode (set to False for free tier)
PAID_FEATURES_ENABLED = True

import os
import sys
import json
import logging
import argparse
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('youtube_analyzer.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class VideoAnalysis:
    """Data class to store video analysis results"""
    video_url: str
    video_id: str
    title: str
    duration: int  # in seconds
    word_count: int
    unique_words: int
    most_common_words: List[Tuple[str, int]]
    potential_techniques: List[str]
    potential_vulnerabilities: List[str]
    security_tools_mentioned: List[str]
    transcript: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    def to_markdown(self) -> str:
        """Convert analysis to markdown report"""
        md = f"# Video Analysis Report\n\n"
        md += f"## {self.title}\n"
        md += f"- **URL**: {self.video_url}\n"
        md += f"- **Duration**: {self.duration // 60}m {self.duration % 60}s\n"
        md += f"- **Word Count**: {self.word_count}\n"
        md += f"- **Unique Words**: {self.unique_words}\n\n"
        
        md += "## Most Common Terms\n"
        for word, count in self.most_common_words[:20]:
            md += f"- `{word}`: {count}\n"
        
        if self.potential_techniques:
            md += "\n## Potential Techniques Mentioned\n"
            for tech in self.potential_techniques:
                md += f"- {tech}\n"
        
        if self.potential_vulnerabilities:
            md += "\n## Potential Vulnerabilities Mentioned\n"
            for vuln in self.potential_vulnerabilities:
                md += f"- {vuln}\n"
        
        if self.security_tools_mentioned:
            md += "\n## Security Tools Mentioned\n"
            for tool in self.security_tools_mentioned:
                md += f"- {tool}\n"
        
        md += "\n## Full Transcript\n\n"
        md += f"```\n{self.transcript}\n```"
        
        return md

class YouTubeAnalyzer:
    """Main class for YouTube video analysis"""
    
    # Common security-related terms to look for
    SECURITY_TERMS = [
        # Vulnerability types
        'xss', 'csrf', 'sqli', 'rce', 'lfi', 'rfi', 'ssrf', 'xxe', 'idor',
        'injection', 'deserialization', 'prototype pollution', 'jwt', 'oauth',
        'jwt', 'cors', 'clickjacking', 'dom-based', 'ssti', 'saml', 'oauth',
        'open redirect', 'subdomain takeover', 'subtake', 'race condition',
        'business logic', 'misconfiguration', 'insecure deserialization',
        'server side request forgery', 'cross site scripting', 'sql injection',
        'remote code execution', 'local file inclusion', 'remote file inclusion',
        'insecure direct object reference'
    ]
    
    TOOLS = [
        # Recon tools
        'nmap', 'masscan', 'sublist3r', 'amass', 'subfinder', 'assetfinder',
        'findomain', 'knockpy', 'shodan', 'crt.sh', 'waybackurls', 'gau',
        'ffuf', 'dirsearch', 'gobuster', 'wfuzz', 'nuclei', 'burp', 'zap',
        'metasploit', 'sqlmap', 'wpscan', 'nikto', 'wappalyzer', 'whatweb',
        # Analysis tools
        'jq', 'grep', 'sed', 'awk', 'python', 'ruby', 'perl', 'bash', 'zsh',
        # Network tools
        'curl', 'wget', 'nc', 'netcat', 'socat', 'openssl', 'tcpdump', 'wireshark'
    ]
    
    def __init__(self, output_dir: str = "youtube_analysis"):
        """Initialize the YouTube analyzer"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.temp_dir = Path(tempfile.mkdtemp(prefix="youtube_analysis_"))
        
        # Check for required tools
        self._check_dependencies()
    
    def _check_dependencies(self) -> None:
        """Check if required tools are installed"""
        required_tools = ["yt-dlp", "ffmpeg"]
        missing = []
        
        for tool in required_tools:
            try:
                subprocess.run(
                    [tool, "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
            except (subprocess.SubprocessError, FileNotFoundError):
                missing.append(tool)
        
        if missing:
            logger.error(f"Missing required tools: {', '.join(missing)}")
            logger.info("Please install them using the following commands:")
            logger.info("  pip install yt-dlp")
            logger.info("  # For Ubuntu/Debian: sudo apt install ffmpeg")
            logger.info("  # For macOS: brew install ffmpeg")
            logger.info("  # For Windows: choco install ffmpeg")
            sys.exit(1)
    
    def _download_audio(self, url: str) -> Tuple[Optional[Path], Dict]:
        """Download audio from YouTube video"""
        output_template = str(self.temp_dir / "%(id)s.%(ext)s")
        info_file = self.temp_dir / "video_info.json"
        
        try:
            # First, get video info
            subprocess.run(
                [
                    "yt-dlp",
                    "--skip-download",
                    "--write-info-json",
                    "--output", str(info_file.with_suffix('')),  # Remove .json extension
                    url
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Load video info
            with open(info_file, 'r', encoding='utf-8') as f:
                info = json.load(f)
            
            # Download audio
            audio_file = self.temp_dir / f"{info['id']}.wav"
            
            subprocess.run(
                [
                    "yt-dlp",
                    "--extract-audio",
                    "--audio-format", "wav",
                    "--audio-quality", "0",
                    "--output", str(audio_file.with_suffix('')),  # Remove .wav extension
                    url
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if not audio_file.exists():
                logger.error(f"Failed to download audio for {url}")
                return None, info
            
            return audio_file, info
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error downloading video: {e.stderr.decode('utf-8')}")
            return None, {}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return None, {}
    
    def _transcribe_audio(self, audio_file: Path) -> str:
        """Transcribe audio to text using whisper.cpp"""
        try:
            # Check if whisper.cpp is available
            result = subprocess.run(
                ["whisper", "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                # Use whisper command if available
                output = subprocess.check_output(
                    ["whisper", str(audio_file), "--model", "base", "--output_format", "txt"],
                    stderr=subprocess.PIPE
                )
                transcript_path = audio_file.with_suffix('.txt')
                if transcript_path.exists():
                    with open(transcript_path, 'r', encoding='utf-8') as f:
                        return f.read()
            
            # Fallback to using OpenAI Whisper API if whisper.cpp is not available
            try:
                import whisper
                model = whisper.load_model("base")
                result = model.transcribe(str(audio_file))
                return result["text"]
            except ImportError:
                logger.warning("Neither whisper.cpp nor openai-whisper is installed. Install with:")
                logger.warning("  pip install openai-whisper")
                logger.warning("Or install whisper.cpp from https://github.com/ggerganov/whisper.cpp")
                return ""
                
        except Exception as e:
            logger.error(f"Error transcribing audio: {str(e)}")
            return ""
    
    def _analyze_text(self, text: str) -> Dict:
        """Analyze transcribed text for security content"""
        from collections import Counter
        import re
        
        # Basic text processing
        words = re.findall(r'\b\w+\b', text.lower())
        word_count = len(words)
        unique_words = len(set(words))
        word_freq = Counter(words)
        
        # Remove common words to find most relevant terms
        common_words = [
            'the', 'and', 'you', 'that', 'was', 'for', 'are', 'with', 'this', 'have',
            'but', 'not', 'they', 'what', 'all', 'were', 'when', 'your', 'can', 'said',
            'there', 'use', 'an', 'each', 'which', 'she', 'do', 'how', 'their', 'if',
            'will', 'up', 'other', 'about', 'out', 'many', 'then', 'them', 'these',
            'some', 'her', 'would', 'make', 'like', 'him', 'into', 'time', 'has',
            'look', 'two', 'more', 'go', 'see', 'number', 'no', 'way', 'could', 'people'
        ]
        
        filtered_freq = {
            k: v for k, v in word_freq.items() 
            if k not in common_words and len(k) > 3 and not k.isdigit()
        }
        
        # Find potential security terms
        potential_techniques = []
        potential_vulnerabilities = []
        security_tools_mentioned = []
        
        for term in self.SECURITY_TERMS:
            if term in text.lower():
                if any(vuln in term for vuln in ['xss', 'csrf', 'sqli', 'rce', 'lfi', 'rfi', 'ssrf', 'xxe', 'idor']):
                    potential_vulnerabilities.append(term.upper())
                else:
                    potential_techniques.append(term)
        
        for tool in self.TOOLS:
            if tool in text.lower():
                security_tools_mentioned.append(tool)
        
        # Remove duplicates
        potential_techniques = list(set(potential_techniques))
        potential_vulnerabilities = list(set(potential_vulnerabilities))
        security_tools_mentioned = list(set(security_tools_mentioned))
        
        return {
            'word_count': word_count,
            'unique_words': unique_words,
            'most_common_words': word_freq.most_common(50),
            'filtered_common_words': sorted(filtered_freq.items(), key=lambda x: x[1], reverse=True)[:50],
            'potential_techniques': potential_techniques,
            'potential_vulnerabilities': potential_vulnerabilities,
            'security_tools_mentioned': security_tools_mentioned
        }
    
    def analyze_video(self, url: str) -> Optional[VideoAnalysis]:
        """Analyze a YouTube video"""
        logger.info(f"Analyzing video: {url}")
        
        # Download audio
        audio_file, video_info = self._download_audio(url)
        if not audio_file or not video_info:
            logger.error("Failed to download video")
            return None
        
        # Transcribe audio
        logger.info("Transcribing audio...")
        transcript = self._transcribe_audio(audio_file)
        
        if not transcript:
            logger.error("Failed to transcribe audio")
            return None
        
        # Analyze text
        logger.info("Analyzing content...")
        analysis = self._analyze_text(transcript)
        
        # Create analysis object
        video_id = video_info.get('id', hashlib.md5(url.encode()).hexdigest()[:8])
        title = video_info.get('title', 'Unknown Title')
        duration = int(video_info.get('duration', 0))
        
        result = VideoAnalysis(
            video_url=url,
            video_id=video_id,
            title=title,
            duration=duration,
            word_count=analysis['word_count'],
            unique_words=analysis['unique_words'],
            most_common_words=analysis['filtered_common_words'][:20],  # Top 20 most relevant terms
            potential_techniques=analysis['potential_techniques'],
            potential_vulnerabilities=analysis['potential_vulnerabilities'],
            security_tools_mentioned=analysis['security_tools_mentioned'],
            transcript=transcript
        )
        
        # Save results
        self._save_results(result)
        
        # Record usage for subscription tracking
        if PAID_FEATURES_ENABLED:
            subscription_manager.record_usage()
            
            # Show usage stats
            tier = subscription_manager.get_subscription_tier()
            used = subscription_manager.usage_data['videos_this_month']
            total = tier['limits']['max_videos_per_month']
            
            print(f"\n{'='*60}")
            print(f"  USAGE: {used}/{total if total != float('inf') else '∞'} videos this month")
            if used / total > 0.8:  # If over 80% of quota used
                print("  WARNING: Approaching monthly limit")
                print("  Upgrade to Enterprise for unlimited analysis")
            print("="*60 + "\n")
        
        return result
    
    def _save_results(self, analysis: VideoAnalysis):
        """Save analysis results to files with IP protection."""
        output_dir = self.output_dir / analysis.video_id
        output_dir.mkdir(exist_ok=True)
        
        # Add dynamic watermark
        watermark = ip_guardian.get_copyright_notice()
        
        # Save transcript with watermark
        with open(output_dir / "transcript.txt", "w", encoding="utf-8") as f:
            f.write(watermark + "\n\n" + analysis.transcript)
            
        # Save analysis report with watermark
        with open(output_dir / "analysis.md", "w", encoding="utf-8") as f:
            f.write(watermark + "\n\n" + analysis.to_markdown())
            
        # Save raw data with fingerprint
        data = analysis.to_dict()
        data['_metadata'] = {
            'generated_by': 'Recon Automation Stack',
            'copyright': f"  {ip_guardian.copyright_year} {ip_guardian.owner}",
            'fingerprint': ip_guardian.fingerprint,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        with open(output_dir / "data.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        # Add readme with legal notice
        with open(output_dir / "LEGAL_NOTICE.txt", "w") as f:
            f.write(ip_guardian.get_copyright_notice())
            f.write("\n" + "="*80 + "\n")
            f.write("LEGAL NOTICE: This output contains proprietary information\n")
            f.write("owned by Khallid H Nurse. Unauthorized use, disclosure, or\n")
            f.write("distribution is strictly prohibited.\n")
            f.write("Fingerprint: " + ip_guardian.fingerprint[:16] + "...\n")
            f.write("Generated: " + datetime.utcnow().isoformat() + "\n")
        
        logger.info(f"Analysis saved to: {output_dir}")

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="YouTube Video Analyzer for Security Research")
    parser.add_argument("url", help="YouTube video URL")
    parser.add_argument("-o", "--output", default="youtube_analysis",
                      help="Output directory (default: youtube_analysis)")
    
    args = parser.parse_args()
    
    analyzer = YouTubeAnalyzer(output_dir=args.output)
    result = analyzer.analyze_video(args.url)
    
    if result:
        print("\n" + "="*80)
        print(f"Analysis Complete: {result.title}")
        print("="*80)
        print(f"Duration: {result.duration // 60}m {result.duration % 60}s")
        print(f"Word Count: {result.word_count}")
        print(f"Unique Words: {result.unique_words}")
        
        if result.potential_techniques:
            print("\nPotential Techniques:", ", ".join(result.potential_techniques))
        
        if result.potential_vulnerabilities:
            print("Potential Vulnerabilities:", ", ".join(result.potential_vulnerabilities))
        
        if result.security_tools_mentioned:
            print("Security Tools Mentioned:", ", ".join(result.security_tools_mentioned))
        
        print("\nTop 10 Most Relevant Terms:")
        for word, count in result.most_common_words[:10]:
            print(f"  {word}: {count}")
        
        print("\nFull report and transcript saved to disk.")
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
