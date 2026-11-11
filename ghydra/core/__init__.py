"""The single core (I1): code that both surfaces share, generated into both.

The bridge ships as **one file** and must not import the ``ghydra`` package, so
the request logic and the small pure helpers are duplicated between
``bridge_mcp_hydra.py`` and this package. That duplication is the project's
biggest structural debt: every bug fixed on one side had to be fixed on the
other, and the parity tests only catch a divergence *after* it exists.

I1 replaces the duplication with one source and a generator. The first module to
make the move is :mod:`ghydra.core.digest` — the canonical-JSON digest and the
"stable view" of an answer, which the runbook, the cache and the mission all
need. ``scripts/gen_core.py`` writes them into the bridge between markers, and
``test_core.py`` fails when the bridge's copy drifts from this source.

The rule for anything added here: **pure functions only**. No I/O, no network,
no globals that a caller must set up — a generated copy of a pure function is
identical on both sides, which is what makes the mechanism safe.
"""