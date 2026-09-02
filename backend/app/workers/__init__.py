"""Worker service components (docs/ARCHITECTURE.md §3.3).

The worker runs four independent, separately limited loops: the scheduler
(collection scheduling, M2T2), the collection pool (M2T2 claim wiring), the
operation pool (M2T6 execution wiring) and the maintenance loop (recovery +
timeout sweeps). All task state lives in PostgreSQL; the task row is the only
execution authorization (ADR-024).
"""
