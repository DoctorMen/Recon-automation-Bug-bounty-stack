<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Content Discovery Methods - Jason Haddix Methodology

## 7 Separate Content Discovery Methods

Based on Jason Haddix's methodology, 7 separate content discovery methods have been implemented:

1. **Tech-Based** - Based on detected technology stack
2. **COTS/Paid/OSS** - Commercial Off-The-Shelf, Paid, and Open Source Software
3. **Custom** - Custom wordlists and endpoint discovery
4. **Historical** - Historical data sources (Wayback Machine, archives)
5. **Recursive** - Recursive directory discovery (prominently mentioned)
6. **Mobile APIs** - Mobile app API endpoints
7. **Change Detection** - Detect changes in endpoints over time

## Usage

### Run All Methods and Compare


### Run Individual Methods


## Output

Each method saves results to:
- output/content_discovery_comparison/{method_name}/discovered_endpoints.json
- output/content_discovery_comparison/{method_name}/summary.json

Comparison report:
- output/content_discovery_comparison/comparison_report.json

## Baseline Comparison

The comparison runner will:
- Run all 7 methods
- Compare endpoint counts
- Identify unique endpoints per method
- Determine which method performs best
- Generate a comparison report

## Integration

These methods run separately from Phase 2 but can be integrated into the full methodology workflow.
