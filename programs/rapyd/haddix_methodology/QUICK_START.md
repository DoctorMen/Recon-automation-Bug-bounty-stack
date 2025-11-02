# Quick Start Guide - Jason Haddix Methodology

## âœ… System Status: READY

All components initialized and verified.

## Quick Start

### 1. Initialize System (First Time)


### 2. Run Full Methodology


This will execute all 5 phases sequentially:
- Phase 1: Reconnaissance
- Phase 2: Content Discovery  
- Phase 3: Parameter Analysis
- Phase 4: Testing Layers
- Phase 5: Heat Mapping

### 3. Run Individual Phases



## Output Locations

Results are saved to:
- output/phase1_recon/ - Subdomain enumeration results
- output/phase2_content/ - API endpoints and directories
- output/phase3_parameters/ - Parameter lists and fuzzing tests
- output/phase4_testing/ - Test cases for all layers
- output/phase5_heatmap/ - Prioritized endpoints

## Configuration

Edit config/methodology_config.yaml to customize:
- Target domains
- Phase settings
- Tool preferences
- Heat mapping priorities

## Requirements

- Python 3.7+
- PyYAML (pip install pyyaml)
- subfinder (for Phase 1)
- httpx (for Phase 1 & 2)
- gobuster (optional, for Phase 2)

## Next Steps

1. Review config/methodology_config.yaml
2. Run python3 initialize.py to verify setup
3. Run python3 scripts/run_full_methodology.py to start
4. Check output/ directories for results

## Integration

This methodology integrates with:
- Existing Rapyd bug bounty testing
- Recon automation stack
- IDOR evidence capture workflows

---
**Ready to start bug hunting!** ðŸŽ¯
