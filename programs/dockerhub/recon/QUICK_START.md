# Docker Hub Reconnaissance - Quick Start

## Purpose
Reverse engineer Docker Hub endpoints, extract passwords/tokens, and gather source code from public repositories for bug bounty research.

## Scope
âœ… Public APIs  
âœ… Public Repositories  
âœ… Public Data  
âœ… Public Source Code  

## Quick Start



## What It Does

1. **Discovers API Endpoints**
   - Maps Docker Hub API structure
   - Tests authentication endpoints
   - Identifies available endpoints

2. **Enumerates Public Repositories**
   - Scans public repos
   - Extracts metadata
   - Identifies interesting targets

3. **Extracts Source Code** (planned)
   - Dockerfiles
   - docker-compose files
   - Build configurations

4. **Finds Credentials** (planned)
   - Passwords in configs
   - API tokens
   - Authentication secrets

## Output

Results saved to output/ directory:
- discovered_endpoints.json - API endpoints found
- public_repos.json - Enumerated repositories

## Requirements



## Legal

- Only targets public data
- Respects rate limits
- Within bug bounty scope
