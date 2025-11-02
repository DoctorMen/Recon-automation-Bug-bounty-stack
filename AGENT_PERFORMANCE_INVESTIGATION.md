# Agent Performance Investigation Report

**Generated:** Investigation Report

## Executive Summary

After investigating the agent system, I found **no references to "sonnet" agents** in the codebase. The `agents.json` file shows agents configured with:
- `gpt-5` model (Strategist, Executor)
- `composer` model (Composer 1-4)

If you're experiencing slow performance with agents configured to use a "sonnet" model (e.g., Claude Sonnet), this would be configured in Cursor's settings, not in this codebase.

## Performance Bottlenecks Identified

### 1. **Long Timeout Configurations**

The agents have very long timeout values that could make them appear stuck:

| Script | Timeout | Default Value |
|--------|---------|---------------|
| `run_recon.py` | `RECON_TIMEOUT` | **1800 seconds (30 minutes)** |
| `run_nuclei.py` | `NUCLEI_SCAN_TIMEOUT` | **3600 seconds (1 hour)** |
| `run_httpx.py` | Individual request timeout | 10 seconds |

**Impact:** Agents may appear stuck when they're actually waiting for long-running operations to complete.

### 2. **Blocking Subprocess Calls**

All agent scripts use synchronous `subprocess.run()` calls that block execution:

```python
# Example from run_recon.py
result = subprocess.run(
    [subfinder_path, "-dL", str(TARGETS_FILE), "-silent", "-o", str(temp_subfinder)],
    timeout=RECON_TIMEOUT,  # Can wait up to 30 minutes
    capture_output=True,
    text=True,
    check=False
)
```

**Impact:** No progress visibility, no way to cancel mid-execution, blocks entire agent.

### 3. **No Progress Monitoring**

- No heartbeat/ping mechanism
- No progress indicators
- No intermediate status updates
- Logs only update when operations complete

### 4. **Sequential Execution**

Agents run sequentially in `run_pipeline.py`:
1. Recon Scanner (can take 30+ minutes)
2. Web Mapper (waits for Recon)
3. Vulnerability Hunter (waits for Web Mapper)
4. Triage (waits for Vulnerability Hunter)
5. Report Writer (waits for Triage)

**Impact:** Total pipeline time = sum of all stage times.

## Recommendations

### Immediate Actions

1. **Check for Stuck Processes**
   ```bash
   # Check if agents are actually running
   python3 scripts/investigate_agent_performance.py
   python3 scripts/scan_monitor.py
   ```

2. **Review Timeout Values**
   Consider reducing timeouts for faster failure detection:
   ```bash
   export RECON_TIMEOUT=600  # 10 minutes instead of 30
   export NUCLEI_SCAN_TIMEOUT=1800  # 30 minutes instead of 60
   ```

3. **Check Output Files**
   Check if agents are producing output:
   ```bash
   ls -lh output/
   tail -f output/recon-run.log
   ```

### Long-term Improvements

1. **Add Progress Indicators**
   - Implement heartbeat mechanism
   - Add progress callbacks to long-running operations
   - Stream output instead of waiting for completion

2. **Implement Non-blocking Operations**
   - Use `subprocess.Popen` for background processes
   - Add process monitoring and cancellation capability
   - Implement timeout handlers with graceful degradation

3. **Parallelize Independent Operations**
   - Run subfinder and amass in parallel
   - Process multiple targets concurrently
   - Use async/await for I/O-bound operations

4. **Add Performance Monitoring**
   - Track execution time per stage
   - Monitor resource usage (CPU, memory, disk)
   - Alert on unusually long operations

## Investigation Script

A diagnostic script has been created at `scripts/investigate_agent_performance.py` that will:
- Check for running processes
- Analyze timeout configurations
- Check output file sizes and modification times
- Show pipeline completion status
- Display recent log entries
- Identify blocking operations

Run it with:
```bash
python3 scripts/investigate_agent_performance.py
```

## If Agents Are Using "Sonnet" Model

If you're referring to agents configured in Cursor (not in this codebase) that use a "sonnet" model:

1. **Check Cursor Settings**: The model assignment happens in Cursor's configuration, not in `agents.json`
2. **Model Performance**: Sonnet models may be slower than other models due to:
   - Larger context windows
   - More complex reasoning
   - API rate limits
   - Network latency

3. **To Investigate Model-Specific Issues**:
   - Check Cursor's agent logs/console
   - Review API response times
   - Verify API quotas/limits
   - Check if agents are waiting for API responses

## Next Steps

1. Run the investigation script to get current status
2. Check logs for error messages
3. Verify tools are installed and working
4. Consider reducing timeout values for faster feedback
5. If issues persist, check Cursor's agent configuration and logs

