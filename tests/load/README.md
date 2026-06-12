# TENET AI Load Testing

## Overview

This directory contains load testing scripts for TENET AI APIs using Locust.

## Tested Endpoints

- GET /health
- GET /v1/stats
- GET /v1/events
- POST /v1/events/llm

## Installation

```bash
pip install locust
```

## Running Tests

```bash
locust -f tests/load/locustfile.py
```

Then open:

http://localhost:8089

## Test Scenarios

### Sustained Load Test

- Target: 100 requests/second
- Duration: 10 minutes

### Spike Load Test

- Simulate sudden bursts of traffic
- Increase users rapidly

### Concurrent Connection Test

- Run multiple concurrent users
- Observe latency and error rates

## Metrics to Measure

- P50 latency
- P95 latency
- P99 latency
- Throughput
- Error rate

## Acceptance Criteria

- P95 latency < 500 ms under sustained load
- Error rate < 0.1% under normal load