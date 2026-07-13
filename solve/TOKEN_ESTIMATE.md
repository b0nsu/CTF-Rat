# Token And Effort Estimate

This file tracks per-challenge effort for cost estimation. It is not exact billing data; exact token usage must come from API/client usage logs.

## How To Record

For each challenge, append one row when starting and update it when stopping.

| Challenge | Status | Start | End | Wall Time | Model | Input Size | Tool Calls | Remote Runs | Failed Paths | Notes |
|---|---|---:|---:|---:|---|---:|---:|---:|---:|---|

## Input Size Scale

- S: existing exploit or tiny patch, little decomp/log reading
- M: several functions/logs read, one exploit chain debugged
- L: many functions/logs, remote mismatch/debug loops
- XL: long reverse/heap exploration, multiple failed hypotheses

## Current Solved Challenges

| Challenge | Status | Start | End | Wall Time | Model | Input Size | Tool Calls | Remote Runs | Failed Paths | Notes |
|---|---|---:|---:|---:|---|---:|---:|---:|---:|---|
| Clockwork Vault | solved | pre-log | pre-log | unknown | unknown | M | unknown | several | 1 | Remote fixed-build offset mismatch; solved via callback leak/candidate call. |
| House Of Mirage | solved | pre-log | pre-log | unknown | unknown | S | unknown | 2 | 0 | Local exploit mostly worked; switched to recvall. |
| Museum Of Echoes | solved | pre-log | pre-log | unknown | unknown | L | unknown | many | 1 | Remote build function offsets differed; found grand_finale offset. |
| Deep Port | solved | pre-log | pre-log | unknown | unknown | L | unknown | many | 2 | Fixed tcache count issue and remote print_flag delta. |

## Active / Next Challenge Log

| Challenge | Status | Start | End | Wall Time | Model | Input Size | Tool Calls | Remote Runs | Failed Paths | Notes |
|---|---|---:|---:|---:|---|---:|---:|---:|---:|---|
