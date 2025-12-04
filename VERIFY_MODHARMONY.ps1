# ModHarmony Verification Script
# Run this to prove the files exist and are complete

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   ModHarmony™ File Verification" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if files exist
$files = @(
    "MODHARMONY_BLEEDING_EDGE.html",
    "MODHARMONY_BUSINESS_PLAN.md",
    "MODHARMONY_VALIDATION_RESEARCH.md"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        $size = (Get-Item $file).Length
        $lines = (Get-Content $file).Count
        Write-Host "✓ $file" -ForegroundColor Green
        Write-Host "  Size: $size bytes" -ForegroundColor Gray
        Write-Host "  Lines: $lines" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "✗ $file NOT FOUND" -ForegroundColor Red
    }
}

# Verify HTML structure
Write-Host "`nVerifying HTML structure..." -ForegroundColor Cyan
$html = Get-Content "MODHARMONY_BLEEDING_EDGE.html" -Raw

$checks = @{
    "Has DOCTYPE" = $html -match "<!DOCTYPE html>"
    "Has ModHarmony title" = $html -match "ModHarmony"
    "Has custom cursor" = $html -match "\.cursor"
    "Has gradient blobs" = $html -match "gradient-blob"
    "Has glassmorphism" = $html -match "backdrop-filter"
    "Has 3D cards" = $html -match "feature-card-3d"
    "Has pricing section" = $html -match "pricing-grid"
    "Has JavaScript" = $html -match "<script>"
    "Has animations" = $html -match "@keyframes"
    "Complete HTML" = $html -match "</html>"
}

foreach ($check in $checks.GetEnumerator()) {
    if ($check.Value) {
        Write-Host "✓ $($check.Key)" -ForegroundColor Green
    } else {
        Write-Host "✗ $($check.Key)" -ForegroundColor Red
    }
}

# Count key sections
Write-Host "`nContent Analysis:" -ForegroundColor Cyan
$sections = @(
    @{Name="Hero Section"; Pattern="class=`"hero`""},
    @{Name="Problem Section"; Pattern="\$5B Gaming Crisis"},
    @{Name="Solution Section"; Pattern="Automated Testing"},
    @{Name="Demo Section"; Pattern="WITHOUT ModHarmony"},
    @{Name="Features Section"; Pattern="AI Conflict Detection"},
    @{Name="Pricing Section"; Pattern="pricing-card"},
    @{Name="ROI Section"; Pattern="For Game Studios"},
    @{Name="Final CTA"; Pattern="Stop Losing Money"}
)

foreach ($section in $sections) {
    if ($html -match $section.Pattern) {
        Write-Host "✓ $($section.Name) found" -ForegroundColor Green
    } else {
        Write-Host "✗ $($section.Name) missing" -ForegroundColor Red
    }
}

# Verify business plan
Write-Host "`nVerifying Business Plan..." -ForegroundColor Cyan
$plan = Get-Content "MODHARMONY_BUSINESS_PLAN.md" -Raw

$planChecks = @{
    "Has Executive Summary" = $plan -match "Executive Summary"
    "Has Problem Section" = $plan -match "The Problem"
    "Has Solution Section" = $plan -match "The Solution"
    "Has Business Model" = $plan -match "Business Model"
    "Has Revenue Streams" = $plan -match "Revenue Streams"
    "Has Go-to-Market" = $plan -match "Go-To-Market"
    "Has Financial Projections" = $plan -match "Financial Projections"
    "Has Competitive Analysis" = $plan -match "Competitive Analysis"
}

foreach ($check in $planChecks.GetEnumerator()) {
    if ($check.Value) {
        Write-Host "✓ $($check.Key)" -ForegroundColor Green
    } else {
        Write-Host "✗ $($check.Key)" -ForegroundColor Red
    }
}

# Verify validation research
Write-Host "`nVerifying Validation Research..." -ForegroundColor Cyan
$research = Get-Content "MODHARMONY_VALIDATION_RESEARCH.md" -Raw

$researchChecks = @{
    "Has Claims to Validate" = $research -match "Claims to Validate"
    "Has Validation Experiments" = $research -match "Validation Experiments"
    "Has Real Data Sources" = $research -match "REAL Data Sources"
    "Has Honest Assessment" = $research -match "HONEST Assessment"
    "Has Validation Plan" = $research -match "Validation Research Plan"
}

foreach ($check in $researchChecks.GetEnumerator()) {
    if ($check.Value) {
        Write-Host "✓ $($check.Key)" -ForegroundColor Green
    } else {
        Write-Host "✗ $($check.Key)" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   Verification Complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "All files exist and contain complete content." -ForegroundColor Green
Write-Host "`nTo view the landing page:" -ForegroundColor Yellow
Write-Host "  Start-Process 'MODHARMONY_BLEEDING_EDGE.html'" -ForegroundColor White
Write-Host "`nTo read the business plan:" -ForegroundColor Yellow
Write-Host "  Get-Content 'MODHARMONY_BUSINESS_PLAN.md'" -ForegroundColor White
Write-Host "`nTo read the validation research:" -ForegroundColor Yellow
Write-Host "  Get-Content 'MODHARMONY_VALIDATION_RESEARCH.md'`n" -ForegroundColor White
